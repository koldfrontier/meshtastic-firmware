#include "KotaLocal.h"

#include <stdlib.h>
#include <string.h>

namespace kota
{

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

Installer::~Installer()
{
    drop();
}

void Installer::drop()
{
    if (flashOpen)
        flash.abort();
    flashOpen = false;
    free(list);
    list = nullptr;
    listLen = listGot = 0;
    manTotal = manGot = 0;
    next = fill = 0;
    reboot = false;
}

Reply Installer::fail(uint8_t code)
{
    drop();
    st = State::FAILED;
    err = code;
    return Reply::STATUS;
}

Reply Installer::handle(const uint8_t *f, size_t len, uint32_t nowMs)
{
    if (!f || len < 1)
        return Reply::NONE;
    const uint8_t *b = f + 1;
    size_t n = len - 1;
    if (active() && source != 0 && f[0] != L_QUERY && f[0] != L_ABORT)
        return Reply::STATUS; // a radio session is open: refuse without touching it
    lastMs = nowMs;
    if (f[0] != L_QUERY)
        source = 0;
    switch (f[0]) {
    case L_MANIFEST:
        return onManifest(b, n);
    case L_LIST:
        return onList(b, n);
    case L_DATA:
        return onData(b, n);
    case L_FINISH:
        return onFinish(b, n);
    case L_ABORT:
        drop();
        st = State::IDLE;
        err = 0;
        return Reply::STATUS;
    case L_QUERY:
        return Reply::STATUS;
    default:
        return Reply::NONE; // mesh frames (K2) and unknown types are not ours
    }
}

Reply Installer::handleRadio(uint32_t src, const uint8_t *f, size_t len, uint32_t nowMs)
{
    if (!f || len < 1 || src == 0)
        return Reply::NONE;
    const uint8_t *b = f + 1;
    size_t n = len - 1;
    if (f[0] == L_QUERY)
        return Reply::STATUS;
    if (f[0] < L_MANIFEST || f[0] > L_ABORT)
        return Reply::NONE;
    if (active() && source != src)
        return Reply::NONE;

    if (f[0] == L_MANIFEST) {
        if (n < 5)
            return Reply::NONE;
        uint16_t off = rd16(b), total = rd16(b + 2);
        size_t dn = n - 4;
        if ((st == State::LIST || st == State::DATA) && total == manTotal && off + dn <= manTotal &&
            memcmp(man + off, b + 4, dn) == 0) { // the same manifest again: keep the session
            lastMs = nowMs;
            return off + dn == manTotal ? Reply::STATUS : Reply::NONE;
        }
        if (off != 0 && (st != State::MANIFEST || total != manTotal || off != manGot))
            return Reply::NONE;
        source = src;
        lastMs = nowMs;
        Reply r = onManifest(b, n);
        if (st == State::FAILED && (err == (uint8_t)Err::BOARD || err == (uint8_t)Err::ENV))
            return Reply::NONE; // a broadcast for another kind of board; QUERY shows the error
        return r;
    }
    if (!(active() || (st == State::DONE && source == src)))
        return Reply::NONE;
    lastMs = nowMs;
    switch (f[0]) {
    case L_LIST: {
        if (n < 5 || st == State::MANIFEST || st == State::DONE)
            return Reply::NONE;
        uint32_t off = rd32(b);
        size_t dn = n - 4;
        if (st == State::DATA) // already complete: answer the last frame again
            return off + dn == listLen ? Reply::STATUS : Reply::NONE;
        if (off != listGot)
            return Reply::NONE;
        return onList(b, n);
    }
    case L_DATA:
        return onData(b, n);
    case L_FINISH:
        if (st == State::DONE || st != State::DATA || next != blockCount(m.rawSize))
            return Reply::STATUS;
        return onFinish(b, n);
    case L_ABORT:
        if (st == State::DONE)
            return Reply::NONE;
        drop();
        st = State::IDLE;
        err = 0;
        return Reply::STATUS;
    default:
        return Reply::NONE;
    }
}

void Installer::tick(uint32_t nowMs)
{
    if (active() && nowMs - lastMs > (source ? RADIO_TIMEOUT_MS : SESSION_TIMEOUT_MS))
        fail((uint8_t)LErr::TIMEOUT);
}

Reply Installer::onManifest(const uint8_t *b, size_t n)
{
    if (n < 4)
        return fail((uint8_t)LErr::FRAME);
    uint16_t off = rd16(b), total = rd16(b + 2);
    const uint8_t *data = b + 4;
    size_t dn = n - 4;
    if (off == 0) { // a manifest from offset 0 starts a new session, whatever came before
        drop();
        if (total < MIN_MANIFEST || total > MAX_MANIFEST)
            return fail((uint8_t)LErr::FRAME);
        manTotal = total;
        st = State::MANIFEST;
        err = 0;
    }
    if (st != State::MANIFEST || total != manTotal || off != manGot)
        return fail((uint8_t)LErr::SEQUENCE);
    if (dn == 0 || manGot + dn > manTotal)
        return fail((uint8_t)LErr::FRAME);
    memcpy(man + manGot, data, dn);
    manGot += dn;
    if (manGot < manTotal)
        return Reply::NONE;

    Manifest parsed;
    Err e = parse(man, manTotal, parsed);
    if (e != Err::OK)
        return fail((uint8_t)e);
    const uint8_t *key = nullptr;
    for (size_t i = 0; i < id.keyCount; i++)
        if (id.keys[i] && keyId(id.keys[i]) == parsed.keyId)
            key = id.keys[i];
    if (!key)
        return fail((uint8_t)LErr::UNKNOWN_KEY);
    e = verify(man, manTotal, key, m);
    if (e == Err::OK)
        e = checkInstall(m, id.boardId, id.env, id.release);
    if (e != Err::OK)
        return fail((uint8_t)e);
    if (m.rawSize > flash.spareSize())
        return fail((uint8_t)LErr::SLOT);
    listLen = (size_t)blockCount(m.rawSize) * HASH;
    list = (uint8_t *)malloc(listLen);
    if (!list)
        return fail((uint8_t)LErr::MEMORY);
    listGot = 0;
    st = State::LIST;
    return Reply::STATUS;
}

Reply Installer::onList(const uint8_t *b, size_t n)
{
    if (st != State::LIST)
        return fail((uint8_t)LErr::SEQUENCE);
    if (n < 5)
        return fail((uint8_t)LErr::FRAME);
    uint32_t off = rd32(b);
    size_t dn = n - 4;
    if (off != listGot)
        return fail((uint8_t)LErr::SEQUENCE);
    if (listGot + dn > listLen)
        return fail((uint8_t)LErr::FRAME);
    memcpy(list + listGot, b + 4, dn);
    listGot += dn;
    if (listGot < listLen)
        return Reply::NONE;
    Err e = checkBlockList(m.rawListSha, m.rawSize, list, listLen);
    if (e != Err::OK)
        return fail((uint8_t)e);
    if (!flash.begin(m.rawSize))
        return fail((uint8_t)LErr::FLASH);
    flashOpen = true;
    raw.reset();
    next = fill = 0;
    st = State::DATA;
    return Reply::STATUS;
}

Reply Installer::onData(const uint8_t *b, size_t n)
{
    if (st != State::DATA || n < 5)
        return Reply::NONE; // stray data after a failure: the client learns from QUERY
    uint16_t idx = rd16(b), off = rd16(b + 2);
    const uint8_t *data = b + 4;
    size_t dn = n - 4;
    if (idx < next) { // a resend of a block already written: acknowledge it again, write nothing
        if (off + dn != blockLength(m.rawSize, idx)) // once, after its last frame (a half-duplex radio must not
            return Reply::NONE;                      // talk over the frames that follow)
        replyBlock = idx;
        replyResult = 0;
        return Reply::BLOCK;
    }
    if (idx != next)
        return Reply::NONE;
    if (off == 0)
        fill = 0; // the client restarts a block from its start
    uint32_t want = blockLength(m.rawSize, idx);
    if (off != fill || dn == 0 || dn > DATA_MAX || fill + dn > want)
        return Reply::NONE; // a lost frame: the client times out and resends the block
    memcpy(block + fill, data, dn);
    fill += dn;
    if (fill < want)
        return Reply::NONE;

    replyBlock = idx;
    Err e = checkBlock(list, m.rawSize, idx, block, want);
    fill = 0;
    if (e != Err::OK) {
        replyResult = (uint8_t)e; // nothing written; the client resends the block
        return Reply::BLOCK;
    }
    if (!flash.write(block, want))
        return fail((uint8_t)LErr::FLASH);
    raw.update(block, want);
    next++;
    replyResult = 0;
    return Reply::BLOCK;
}

Reply Installer::onFinish(const uint8_t *b, size_t n)
{
    if (st != State::DATA || next != blockCount(m.rawSize))
        return fail((uint8_t)LErr::SEQUENCE);
    Err e = raw.finish(m.rawSha, m.rawSize);
    if (e != Err::OK)
        return fail((uint8_t)e);
    flashOpen = false;
    if (!flash.end() || !flash.setBoot())
        return fail((uint8_t)LErr::FLASH);
    free(list);
    list = nullptr;
    st = State::DONE;
    err = 0;
    reboot = n >= 1 && b[0] == 1;
    return Reply::STATUS;
}

size_t Installer::encodeStatus(const PlatformStatus &ps, uint8_t *o, size_t max) const
{
    size_t vl = strlen(ps.version);
    if (vl > MAX_STR)
        vl = MAX_STR;
    size_t need = 1 + 1 + 1 + 2 + 2 + 1 + 1 + 1 + 1 + 2 + 4 + 1 + 8 + 1 + vl;
    if (max < need)
        return 0;
    size_t i = 0;
    o[i++] = L_STATUS;
    o[i++] = (uint8_t)st;
    o[i++] = err;
    wr16(o + i, (uint16_t)next);
    i += 2;
    wr16(o + i, (uint16_t)blocks());
    i += 2;
    o[i++] = ps.runningSlot;
    o[i++] = ps.bootSlot;
    o[i++] = ps.imageState;
    o[i++] = ps.health;
    wr16(o + i, id.boardId);
    i += 2;
    wr32(o + i, id.release);
    i += 4;
    o[i++] = ps.testKey;
    memcpy(o + i, ps.elfSha, 8);
    i += 8;
    o[i++] = (uint8_t)vl;
    memcpy(o + i, ps.version, vl);
    return i + vl;
}

size_t Installer::encodeBlock(uint8_t *o, size_t max) const
{
    if (max < 4)
        return 0;
    o[0] = L_BLOCK;
    wr16(o + 1, replyBlock);
    o[3] = replyResult;
    return 4;
}

} // namespace kota
