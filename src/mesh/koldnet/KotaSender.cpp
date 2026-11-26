// koldnet field updater, pure logic (SPEC-0003 #ota-updater). See KotaSender.h.
#include "KotaSender.h"

#include <SHA256.h>
#include <stdio.h>
#include <string.h>

namespace kota
{

namespace
{
uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}
uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
void wr16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xff;
    p[1] = v >> 8;
}
void wr32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
constexpr size_t MAN_CHUNK = 200; // scripts/kota.py frames_manifest
constexpr uint32_t CHECK_STEP = 8192;
constexpr uint8_t S_LIST = 2, S_DATA = 3, S_DONE = 4, S_FAILED = 5;
} // namespace

bool parseStatus(const uint8_t *b, size_t n, Heard &h)
{
    if (n < 27 || b[0] != L_STATUS)
        return false;
    size_t vl = b[26];
    if (vl > MAX_STR || 27 + vl > n)
        return false;
    h.state = b[1];
    h.err = b[2];
    h.next = rd16(b + 3);
    h.blocks = rd16(b + 5);
    h.runningSlot = b[7];
    h.bootSlot = b[8];
    h.imageState = b[9];
    h.health = b[10];
    h.board = rd16(b + 11);
    h.release = rd32(b + 13);
    h.testKey = b[17];
    memcpy(h.version, b + 27, vl);
    h.version[vl] = 0;
    h.env[0] = 0;
    size_t i = 27 + vl;
    if (i < n) { // U1: the env after the version
        size_t el = b[i];
        if (el <= MAX_STR && i + 1 + el <= n) {
            memcpy(h.env, b + i + 1, el);
            h.env[el] = 0;
        }
    }
    h.rawLen = (uint8_t)(n < STATUS_MAX ? n : STATUS_MAX);
    memcpy(h.raw, b, h.rawLen);
    return true;
}

// ---- Sender ----------------------------------------------------------------------------------

bool Sender::scan(uint8_t rounds, uint32_t roundMs, uint32_t nowMs)
{
    if (busy() || rounds == 0)
        return false;
    nHeard = 0;
    nTargets = 0;
    scanLeft = rounds;
    scanRoundMs = roundMs;
    reason = Why::NONE;
    ph = Phase::SCAN;
    startMs = nowMs;
    waitUntilMs = nowMs;
    sending = false;
    return true;
}

bool Sender::push(ImageSource *s, const uint32_t *nodes, size_t n, const SenderConfig &c, uint32_t nowMs)
{
    if (busy() || !s || n == 0 || n > MAX_TARGETS)
        return false;
    manLen = s->manifest(man, sizeof man);
    if (manLen == 0 || parse(man, manLen, m) != Err::OK)
        return false;
    nBlocks = blockCount(m.rawSize);
    if (s->rawSize() != m.rawSize || s->listSize() != nBlocks * HASH)
        return false;
    src = s;
    cfg = c;
    if (cfg.loadPermille == 0 || cfg.loadPermille > 1000)
        cfg.loadPermille = 600;
    nTargets = 0;
    for (size_t i = 0; i < n; i++) {
        if (nodes[i] == 0 || find(nodes[i]))
            continue;
        targets[nTargets] = Target();
        targets[nTargets++].node = nodes[i];
    }
    resends = 0;
    cur = 0;
    reason = Why::NONE;
    startMs = nowMs;
    check.reset();
    checkOff = 0;
    sending = false;
    ph = Phase::CHECK;
    return true;
}

void Sender::cancel()
{
    if (busy()) {
        ph = Phase::CANCELLED;
        reason = Why::CANCELLED;
        sending = false;
    }
}

Target *Sender::find(uint32_t node)
{
    for (size_t i = 0; i < nTargets; i++)
        if (targets[i].node == node)
            return &targets[i];
    return nullptr;
}

Heard *Sender::heardSlot(uint32_t node)
{
    for (size_t i = 0; i < nHeard; i++)
        if (table[i].node == node)
            return &table[i];
    if (nHeard < MAX_HEARD) {
        table[nHeard] = Heard();
        table[nHeard].node = node;
        return &table[nHeard++];
    }
    return nullptr;
}

void Sender::onReply(uint32_t from, const uint8_t *b, size_t n, int16_t rssi, int16_t snr4, uint32_t nowMs)
{
    if (n < 1)
        return;
    if (b[0] == L_STATUS) {
        Heard h;
        if (!parseStatus(b, n, h))
            return;
        h.node = from;
        h.atMs = nowMs;
        h.rssi = rssi;
        h.snr4 = snr4;
        Heard *slot = heardSlot(from);
        if (slot)
            *slot = h;
        Target *t = find(from);
        if (t) {
            t->fresh = true;
            t->state = h.state;
            t->err = h.err;
            t->next = h.next;
        }
    } else if (b[0] == L_BLOCK && n >= 4) {
        Target *t = find(from);
        if (t && ph == Phase::DATA && b[3] == 0 && rd16(b + 1) == cur)
            t->acked = true;
    }
}

void Sender::startBatch(Batch b, uint32_t nowMs)
{
    batch = b;
    bOff = 0;
    switch (b) {
    case Batch::QUERY:
    case Batch::FINISH:
        bEnd = 1;
        break;
    case Batch::MANIFEST:
        // From the second attempt a QUERY follows: a target that refused the manifest (another board or env)
        // stays silent to it, and only QUERY shows its error (SPEC-0003 #ota-mesh, "Who answers").
        bEnd = (uint32_t)manLen + (attempt >= 2 ? 1 : 0);
        break;
    case Batch::LIST:
        bEnd = nBlocks * HASH;
        break;
    case Batch::BLOCK:
        bEnd = blockLen;
        break;
    default:
        bEnd = 0;
    }
    sending = bEnd > 0;
    (void)nowMs;
}

size_t Sender::frameAt(uint8_t *f, size_t max)
{
    (void)max;
    switch (batch) {
    case Batch::QUERY:
        f[0] = L_QUERY;
        bOff = 1;
        return 1;
    case Batch::FINISH:
        f[0] = L_FINISH;
        f[1] = 1; // reboot
        bOff = 1;
        return 2;
    case Batch::MANIFEST: {
        if (bOff >= manLen) {
            f[0] = L_QUERY;
            bOff = bEnd;
            return 1;
        }
        size_t c = manLen - bOff < MAN_CHUNK ? manLen - bOff : MAN_CHUNK;
        f[0] = L_MANIFEST;
        wr16(f + 1, (uint16_t)bOff);
        wr16(f + 3, (uint16_t)manLen);
        memcpy(f + 5, man + bOff, c);
        bOff += c;
        return 5 + c;
    }
    case Batch::LIST: {
        size_t c = bEnd - bOff < DATA_MAX ? bEnd - bOff : DATA_MAX;
        f[0] = L_LIST;
        wr32(f + 1, bOff);
        if (!src->readList(bOff, f + 5, c))
            return 0;
        bOff += c;
        return 5 + c;
    }
    case Batch::BLOCK: {
        size_t c = bEnd - bOff < DATA_MAX ? bEnd - bOff : DATA_MAX;
        f[0] = L_DATA;
        wr16(f + 1, (uint16_t)cur);
        wr16(f + 3, (uint16_t)bOff);
        memcpy(f + 5, blockBuf + bOff, c);
        bOff += c;
        return 5 + c;
    }
    default:
        return 0;
    }
}

bool Sender::sendOne(uint32_t nowMs)
{
    uint8_t f[5 + DATA_MAX];
    size_t n = frameAt(f, sizeof f);
    if (n == 0) {
        fail(Why::SOURCE);
        return false;
    }
    out.send(f, n);
    uint32_t base = (int32_t)(nextAtMs - nowMs) > 0 ? nextAtMs : nowMs;
    nextAtMs = base + out.airtimeMs(n) * 1000 / cfg.loadPermille;
    if (bOff >= bEnd) {
        sending = false;
        uint32_t after = (int32_t)(nextAtMs - nowMs) > 0 ? nextAtMs : nowMs;
        waitUntilMs = after + (ph == Phase::SCAN ? scanRoundMs : timeout());
    }
    return true;
}

uint32_t Sender::timeout() const
{
    switch (ph) {
    case Phase::QUERY:
        return cfg.queryTimeoutMs / (cfg.queryAttempts ? cfg.queryAttempts : 1);
    case Phase::MANIFEST:
    case Phase::LIST:
        return cfg.blockTimeoutMs * 2;
    case Phase::FINISH:
        return cfg.blockTimeoutMs * 4;
    default:
        return cfg.blockTimeoutMs;
    }
}

uint8_t Sender::attemptsFor() const
{
    switch (ph) {
    case Phase::QUERY:
        return cfg.queryAttempts;
    case Phase::DATA:
        return cfg.retries + 1;
    default:
        return cfg.retries;
    }
}

bool Sender::met() const
{
    for (size_t i = 0; i < nTargets; i++) {
        const Target &t = targets[i];
        switch (ph) {
        case Phase::QUERY:
            if (!t.fresh)
                return false;
            break;
        case Phase::MANIFEST:
            if (!t.fresh || (t.state != S_LIST && t.state != S_DATA))
                return false;
            break;
        case Phase::LIST:
            if (!t.fresh || t.state != S_DATA)
                return false;
            break;
        case Phase::DATA:
            if (!t.acked)
                return false;
            break;
        case Phase::FINISH:
            if (!t.fresh || t.state != S_DONE)
                return false;
            break;
        default:
            return false;
        }
    }
    return nTargets > 0;
}

bool Sender::anyFailed() const
{
    if (ph != Phase::MANIFEST && ph != Phase::LIST && ph != Phase::FINISH)
        return false;
    for (size_t i = 0; i < nTargets; i++)
        if (targets[i].fresh && targets[i].state == S_FAILED)
            return true;
    return false;
}

void Sender::fail(Why w)
{
    ph = Phase::FAILED;
    reason = w;
    sending = false;
}

void Sender::enter(Phase p, uint32_t nowMs)
{
    ph = p;
    attempt = 1;
    switch (p) {
    case Phase::QUERY:
    case Phase::MANIFEST:
    case Phase::FINISH:
        for (size_t i = 0; i < nTargets; i++)
            targets[i].fresh = false; // a new answer is wanted (kota_mesh.py clears its status here)
        startBatch(p == Phase::QUERY ? Batch::QUERY : p == Phase::MANIFEST ? Batch::MANIFEST : Batch::FINISH, nowMs);
        break;
    case Phase::LIST:
        startBatch(Batch::LIST, nowMs);
        break;
    case Phase::DATA: {
        blockLen = blockLength(m.rawSize, cur);
        if (!src->readRaw(cur * BLOCK, blockBuf, blockLen)) {
            fail(Why::SOURCE);
            return;
        }
        for (size_t i = 0; i < nTargets; i++)
            targets[i].acked = false;
        startBatch(Batch::BLOCK, nowMs);
        break;
    }
    default:
        break;
    }
}

void Sender::nextPhase(uint32_t nowMs)
{
    switch (ph) {
    case Phase::QUERY:
        enter(Phase::MANIFEST, nowMs);
        break;
    case Phase::MANIFEST: {
        bool allData = true;
        for (size_t i = 0; i < nTargets; i++)
            allData = allData && targets[i].state == S_DATA;
        if (!allData) {
            enter(Phase::LIST, nowMs);
            break;
        }
    }
        // fall through: every target is in DATA already (a resumed session)
    case Phase::LIST: {
        uint32_t start = nBlocks;
        for (size_t i = 0; i < nTargets; i++)
            if (targets[i].next < start)
                start = targets[i].next;
        cur = start;
        if (cur >= nBlocks)
            enter(Phase::FINISH, nowMs);
        else
            enter(Phase::DATA, nowMs);
        break;
    }
    case Phase::DATA:
        cur++;
        if (cur >= nBlocks)
            enter(Phase::FINISH, nowMs);
        else
            enter(Phase::DATA, nowMs);
        break;
    case Phase::FINISH:
        ph = Phase::DONE;
        break;
    default:
        break;
    }
}

uint32_t Sender::step(uint32_t nowMs)
{
    if (!busy())
        return 1000;
    if (ph == Phase::CHECK) {
        uint32_t n = m.rawSize - checkOff < CHECK_STEP ? m.rawSize - checkOff : CHECK_STEP;
        for (uint32_t done = 0; done < n;) {
            uint32_t c = n - done < BLOCK ? n - done : BLOCK;
            if (!src->readRaw(checkOff, blockBuf, c)) {
                fail(Why::SOURCE);
                return 1000;
            }
            check.update(blockBuf, c);
            checkOff += c;
            done += c;
        }
        if (checkOff >= m.rawSize) {
            if (check.finish(m.rawSha, m.rawSize) != Err::OK) {
                fail(Why::IMAGE_HASH);
                return 1000;
            }
            enter(Phase::QUERY, nowMs);
        }
        return 0;
    }
    if (sending) {
        if ((int32_t)(nextAtMs - nowMs) > 0)
            return nextAtMs - nowMs;
        if (!out.ready())
            return 20;
        sendOne(nowMs);
        return 0;
    }
    if (ph == Phase::SCAN) {
        if ((int32_t)(nowMs - waitUntilMs) < 0)
            return waitUntilMs - nowMs;
        if (scanLeft == 0) {
            ph = Phase::IDLE;
            return 1000;
        }
        scanLeft--;
        startBatch(Batch::QUERY, nowMs);
        return 0;
    }
    if (met()) {
        nextPhase(nowMs);
        return 0;
    }
    if (anyFailed()) {
        fail(Why::TARGET_FAILED);
        return 1000;
    }
    if ((int32_t)(nowMs - waitUntilMs) < 0) {
        uint32_t w = waitUntilMs - nowMs;
        return w < 50 ? w : 50;
    }
    if (attempt < attemptsFor()) {
        attempt++;
        if (ph == Phase::DATA)
            resends++;
        startBatch(batch, nowMs);
        return 0;
    }
    fail(ph == Phase::QUERY ? Why::NO_ANSWER : ph == Phase::DATA ? Why::BLOCK_RETRIES : Why::RETRIES);
    return 1000;
}

size_t Sender::encodeProgress(uint32_t nowMs, uint8_t *o, size_t max) const
{
    size_t need = 14 + 8 * nTargets;
    if (max < need)
        return 0;
    o[0] = U_PROG;
    o[1] = (uint8_t)ph;
    o[2] = (uint8_t)reason;
    o[3] = (uint8_t)nTargets;
    wr16(o + 4, (uint16_t)cur);
    wr16(o + 6, (uint16_t)nBlocks);
    wr16(o + 8, (uint16_t)resends);
    wr32(o + 10, (nowMs - startMs) / 1000);
    size_t i = 14;
    for (size_t k = 0; k < nTargets; k++) {
        wr32(o + i, targets[k].node);
        o[i + 4] = targets[k].state;
        o[i + 5] = targets[k].err;
        wr16(o + i + 6, targets[k].next);
        i += 8;
    }
    return i;
}

// ---- Library ---------------------------------------------------------------------------------

static void path(char *out, size_t max, const char *name, const char *file)
{
    snprintf(out, max, "%s/%s/%s", Library::ROOT, name, file);
}

size_t Library::scan(Storage &s, const uint8_t *const *keys, size_t keyCount)
{
    char names[MAX_LIB][LIB_NAME];
    size_t found = s.listDirs(ROOT, names, MAX_LIB);
    n = 0;
    for (size_t k = 0; k < found && n < MAX_LIB; k++) {
        LibEntry &x = e[n++];
        x = LibEntry();
        strncpy(x.name, names[k], LIB_NAME - 1);
        char p[LIB_NAME + 32];
        uint8_t buf[MAX_MANIFEST];
        path(p, sizeof p, x.name, "manifest.bin");
        int32_t ms = s.size(p);
        if (ms < (int32_t)MIN_MANIFEST || ms > (int32_t)MAX_MANIFEST) {
            x.err = LIB_NO_MANIFEST;
            continue;
        }
        if (!s.read(p, 0, buf, (size_t)ms)) {
            x.err = LIB_READ;
            continue;
        }
        Err v = Err::KEY_ID;
        for (size_t i = 0; i < keyCount && v != Err::OK; i++)
            v = verify(buf, (size_t)ms, keys[i], x.m);
        if (v != Err::OK) {
            if (parse(buf, (size_t)ms, x.m) != Err::OK)
                x.m = Manifest();
            x.err = (uint8_t)v;
            continue;
        }
        path(p, sizeof p, x.name, "raw.bin");
        if (s.size(p) != (int32_t)x.m.rawSize) {
            x.err = LIB_RAW_SIZE;
            continue;
        }
        path(p, sizeof p, x.name, "raw.blocks");
        uint32_t want = blockCount(x.m.rawSize) * HASH;
        if (s.size(p) != (int32_t)want) {
            x.err = LIB_LIST_SIZE;
            continue;
        }
        SHA256 h;
        uint8_t chunk[256];
        bool ok = true;
        for (uint32_t off = 0; off < want && ok; off += sizeof chunk) {
            size_t c = want - off < sizeof chunk ? want - off : sizeof chunk;
            ok = s.read(p, off, chunk, c);
            h.update(chunk, c);
        }
        uint8_t got[HASH];
        h.finalize(got, sizeof got);
        if (!ok)
            x.err = LIB_READ;
        else if (memcmp(got, x.m.rawListSha, HASH) != 0)
            x.err = (uint8_t)Err::BLOCK_LIST;
    }
    return n;
}

bool Library::fits(size_t i, const Heard &h) const
{
    if (i >= n || e[i].err != 0)
        return false;
    const Manifest &m = e[i].m;
    if (m.boardId != h.board)
        return false;
    if (h.env[0] && strcmp(m.env, h.env) != 0)
        return false;
    return m.release > h.release;
}

LibSource::LibSource(Storage &s, const LibEntry &e) : s(s), m(e.m)
{
    path(man, sizeof man, e.name, "manifest.bin");
    path(list, sizeof list, e.name, "raw.blocks");
    path(raw, sizeof raw, e.name, "raw.bin");
}

size_t LibSource::manifest(uint8_t *out, size_t max)
{
    int32_t n = s.size(man);
    if (n <= 0 || (size_t)n > max || !s.read(man, 0, out, (size_t)n))
        return 0;
    return (size_t)n;
}

uint32_t LibSource::listSize()
{
    int32_t n = s.size(list);
    return n < 0 ? 0 : (uint32_t)n;
}

bool LibSource::readList(uint32_t off, uint8_t *out, size_t n)
{
    return s.read(list, off, out, n);
}

bool LibSource::readRaw(uint32_t off, uint8_t *out, size_t n)
{
    return s.read(raw, off, out, n);
}

uint8_t SelfSource::put(uint8_t part, uint32_t off, const uint8_t *b, size_t n, const uint8_t *const *keys,
                        size_t keyCount)
{
    if (part == 0) {
        if (off == 0) { // a new upload
            manLen = 0;
            manOk = false;
            delete[] list;
            list = nullptr;
            listLen = listGot = 0;
        }
        if (off != manLen || off + n > MAX_MANIFEST)
            return (uint8_t)LErr::SEQUENCE;
        memcpy(man + off, b, n);
        manLen += n;
        Err v = Err::KEY_ID;
        for (size_t i = 0; i < keyCount && v != Err::OK; i++)
            v = verify(man, manLen, keys[i], m);
        manOk = v == Err::OK; // complete when it verifies; until then more chunks are expected
        if (manOk) {
            listLen = blockCount(m.rawSize) * HASH;
            list = new uint8_t[listLen];
            if (!list)
                return (uint8_t)LErr::MEMORY;
        }
        return 0;
    }
    if (part != 1 || !manOk || !list || off != listGot || off + n > listLen)
        return (uint8_t)LErr::SEQUENCE;
    memcpy(list + off, b, n);
    listGot += n;
    if (listGot == listLen && checkBlockList(m.rawListSha, m.rawSize, list, listLen) != Err::OK) {
        listGot = 0; // refused: upload the list again
        return (uint8_t)Err::BLOCK_LIST;
    }
    return 0;
}

size_t SelfSource::manifest(uint8_t *out, size_t max)
{
    if (!manOk || max < manLen)
        return 0;
    memcpy(out, man, manLen);
    return manLen;
}

bool SelfSource::readList(uint32_t off, uint8_t *out, size_t n)
{
    if (!complete() || off + n > listLen)
        return false;
    memcpy(out, list + off, n);
    return true;
}

size_t encodeLibEntry(const Library &lib, size_t i, uint8_t *o, size_t max)
{
    if (i >= lib.count())
        return 0;
    const LibEntry &x = lib.entry(i);
    size_t el = strlen(x.m.env), vl = strlen(x.m.version), nl = strlen(x.name);
    size_t need = 15 + 1 + el + 1 + vl + 1 + nl;
    if (max < need)
        return 0;
    o[0] = U_LIBENT;
    o[1] = (uint8_t)i;
    o[2] = (uint8_t)lib.count();
    o[3] = x.err;
    wr16(o + 4, x.m.boardId);
    wr32(o + 6, x.m.release);
    wr32(o + 10, x.m.rawSize);
    o[14] = x.m.flags;
    size_t k = 15;
    o[k++] = (uint8_t)el;
    memcpy(o + k, x.m.env, el);
    k += el;
    o[k++] = (uint8_t)vl;
    memcpy(o + k, x.m.version, vl);
    k += vl;
    o[k++] = (uint8_t)nl;
    memcpy(o + k, x.name, nl);
    return k + nl;
}

size_t encodeNode(const Sender &s, size_t i, uint32_t nowMs, uint8_t *o, size_t max)
{
    if (i >= s.heardCount())
        return 0;
    const Heard &h = s.heard(i);
    size_t need = 13 + h.rawLen;
    if (max < need)
        return 0;
    o[0] = U_NODE;
    o[1] = (uint8_t)i;
    o[2] = (uint8_t)s.heardCount();
    wr32(o + 3, h.node);
    wr16(o + 7, (uint16_t)h.rssi);
    wr16(o + 9, (uint16_t)h.snr4);
    uint32_t age = (nowMs - h.atMs) / 1000;
    wr16(o + 11, (uint16_t)(age > 0xffff ? 0xffff : age));
    memcpy(o + 13, h.raw, h.rawLen);
    return need;
}

} // namespace kota
