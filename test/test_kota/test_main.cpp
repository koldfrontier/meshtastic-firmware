// koldnet SPEC-0003 #ota-format: the signed manifest, block lists, install rules and the in-place
// bound, on the host. The vectors come from scripts/kota.py in koldnet (vectors.h, generated), and
// are signed with a throwaway test key derived from KOTA_TEST_SEED_TEXT, never a release key.
#include "TestUtil.h"
#include "configuration.h" // Arduino.h: setup() and loop() with C linkage
#include "mesh/koldnet/KotaImage.h"
#include "mesh/koldnet/KotaLocal.h"
#include "mesh/koldnet/KotaSender.h"
#include <stdio.h>
#include "vectors.h"
#include <Ed25519.h>
#include <SHA256.h>
#include <string.h>
#include <unity.h>

using namespace kota;

#define ASSERT_ERR(exp, act) TEST_ASSERT_EQUAL_INT((int)(exp), (int)(act))

static uint8_t PUB[32];

void setUp(void) {}
void tearDown(void) {}

static void derive_test_key()
{
    uint8_t priv[32];
    SHA256 h;
    h.update(KOTA_TEST_SEED_TEXT, strlen(KOTA_TEST_SEED_TEXT));
    h.finalize(priv, sizeof priv);
    Ed25519::derivePublicKey(PUB, priv);
}

static void test_golden_manifest_verifies_and_parses()
{
    Manifest m;
    ASSERT_ERR(Err::OK, verify(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, PUB, m));
    TEST_ASSERT_EQUAL_UINT16(1, m.boardId);
    TEST_ASSERT_EQUAL_UINT32(5, m.release);
    TEST_ASSERT_EQUAL_UINT32(GOLDEN_RAW_SIZE, m.rawSize);
    TEST_ASSERT_EQUAL_UINT32(GOLDEN_STREAM_SIZE, m.streamSize);
    TEST_ASSERT_EQUAL_STRING("heltec-v3", m.env);
    TEST_ASSERT_EQUAL_STRING("2.7.26.64f6f9c", m.version);
    TEST_ASSERT_EQUAL_UINT8(0, m.flags);
    TEST_ASSERT_EQUAL_UINT32(keyId(PUB), m.keyId);
}

// Acceptance 1: a failed signature is refused.
static void test_any_changed_byte_fails_the_signature()
{
    uint8_t buf[sizeof GOLDEN_MANIFEST];
    Manifest m;
    // Every byte under the signature, apart from those that fail parsing first, and the signature itself.
    for (size_t i = 0; i < sizeof buf; i++) {
        memcpy(buf, GOLDEN_MANIFEST, sizeof buf);
        buf[i] ^= 0x01;
        Err e = verify(buf, sizeof buf, PUB, m);
        TEST_ASSERT_TRUE_MESSAGE(e != Err::OK, "a changed byte verified");
    }
    memcpy(buf, GOLDEN_MANIFEST, sizeof buf);
    buf[8] ^= 0x01; // the release counter: parses, so it is the signature that refuses it
    ASSERT_ERR(Err::SIGNATURE, verify(buf, sizeof buf, PUB, m));
}

static void test_other_key_is_refused_by_key_id()
{
    uint8_t other[32];
    memcpy(other, PUB, 32);
    other[0] ^= 1;
    Manifest m;
    ASSERT_ERR(Err::KEY_ID, verify(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, other, m));
}

// Acceptance 1: wrong board, and a lower counter without the downgrade flag.
static void test_install_rules()
{
    Manifest m;
    ASSERT_ERR(Err::OK, verify(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, PUB, m));
    ASSERT_ERR(Err::OK, checkInstall(m, 1, "heltec-v3", 4));
    ASSERT_ERR(Err::BOARD, checkInstall(m, 2, "heltec-v3", 4));
    ASSERT_ERR(Err::ENV, checkInstall(m, 1, "heltec-v3-koldnet-ap", 4));
    ASSERT_ERR(Err::NOT_NEWER, checkInstall(m, 1, "heltec-v3", 5));
    ASSERT_ERR(Err::NOT_NEWER, checkInstall(m, 1, "heltec-v3", 6));

    Manifest d;
    ASSERT_ERR(Err::OK, verify(GOLDEN_DOWNGRADE_MANIFEST, sizeof GOLDEN_DOWNGRADE_MANIFEST, PUB, d));
    TEST_ASSERT_EQUAL_UINT32(3, d.release);
    TEST_ASSERT_EQUAL_UINT8(FLAG_DOWNGRADE, d.flags);
    ASSERT_ERR(Err::OK, checkInstall(d, 1, "heltec-v3", 6));
}

static void test_malformed_manifests_are_refused_before_the_signature()
{
    uint8_t buf[MAX_MANIFEST + 1];
    Manifest m;
    ASSERT_ERR(Err::LENGTH, parse(GOLDEN_MANIFEST, MIN_MANIFEST - 1, m));
    memset(buf, 0, sizeof buf);
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    ASSERT_ERR(Err::VERSION_LENGTH, parse(buf, sizeof GOLDEN_MANIFEST + 1, m)); // a trailing byte
    ASSERT_ERR(Err::LENGTH, parse(buf, sizeof buf, m));

    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    buf[3] = 'B';
    ASSERT_ERR(Err::MAGIC, parse(buf, sizeof GOLDEN_MANIFEST, m));
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    buf[5] = 0x02;
    ASSERT_ERR(Err::FLAG, parse(buf, sizeof GOLDEN_MANIFEST, m));
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    buf[HEAD] = 0;
    ASSERT_ERR(Err::ENV_LENGTH, parse(buf, sizeof GOLDEN_MANIFEST, m));
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    buf[HEAD] = 40;
    ASSERT_ERR(Err::ENV_LENGTH, parse(buf, sizeof GOLDEN_MANIFEST, m));
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    buf[HEAD + 2] = 0; // a NUL inside the env
    ASSERT_ERR(Err::ENV_LENGTH, parse(buf, sizeof GOLDEN_MANIFEST, m));
    memcpy(buf, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    memset(buf + 16, 0, 4); // raw size 0
    ASSERT_ERR(Err::EMPTY, parse(buf, sizeof GOLDEN_MANIFEST, m));
}

// Acceptance 1: a hash mismatch is refused, for the block lists, each block, and the whole stream.
static void test_block_lists_and_blocks()
{
    Manifest m;
    ASSERT_ERR(Err::OK, verify(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, PUB, m));
    TEST_ASSERT_EQUAL_UINT32(3, blockCount(m.rawSize));    // 10000 B
    TEST_ASSERT_EQUAL_UINT32(2, blockCount(m.streamSize)); // 5116 B
    TEST_ASSERT_EQUAL_UINT32(10000 - 8192, blockLength(m.rawSize, 2));
    TEST_ASSERT_EQUAL_UINT32(0, blockLength(m.rawSize, 3));

    ASSERT_ERR(Err::OK, checkBlockList(m.rawListSha, m.rawSize, GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS));
    ASSERT_ERR(Err::OK, checkBlockList(m.streamListSha, m.streamSize, GOLDEN_STREAM_BLOCKS, sizeof GOLDEN_STREAM_BLOCKS));
    static uint8_t badList[sizeof GOLDEN_RAW_BLOCKS];
    memcpy(badList, GOLDEN_RAW_BLOCKS, sizeof badList);
    badList[40] ^= 0x01;
    ASSERT_ERR(Err::BLOCK_LIST, checkBlockList(m.rawListSha, m.rawSize, badList, sizeof badList));
    ASSERT_ERR(Err::SIZE, checkBlockList(m.rawListSha, m.rawSize, GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS - 32));

    for (uint32_t i = 0; i < blockCount(m.streamSize); i++)
        ASSERT_ERR(Err::OK, checkBlock(GOLDEN_STREAM_BLOCKS, m.streamSize, i, GOLDEN_STREAM + i * BLOCK,
                                       blockLength(m.streamSize, i)));
    static uint8_t bad[BLOCK];
    memcpy(bad, GOLDEN_STREAM, BLOCK);
    bad[100] ^= 0x80;
    ASSERT_ERR(Err::HASH_MISMATCH, checkBlock(GOLDEN_STREAM_BLOCKS, m.streamSize, 0, bad, BLOCK));
    ASSERT_ERR(Err::SIZE, checkBlock(GOLDEN_STREAM_BLOCKS, m.streamSize, 1, GOLDEN_STREAM + BLOCK, BLOCK));
    ASSERT_ERR(Err::BLOCK_INDEX, checkBlock(GOLDEN_STREAM_BLOCKS, m.streamSize, 2, GOLDEN_STREAM, 1));

    ObjectHash whole;
    whole.update(GOLDEN_STREAM, 1000); // in pieces, as it is read from flash
    whole.update(GOLDEN_STREAM + 1000, sizeof GOLDEN_STREAM - 1000);
    ASSERT_ERR(Err::OK, whole.finish(m.streamSha, m.streamSize));
    ObjectHash shortRead;
    shortRead.update(GOLDEN_STREAM, sizeof GOLDEN_STREAM - 1);
    ASSERT_ERR(Err::SIZE, shortRead.finish(m.streamSha, m.streamSize));
    ObjectHash changed;
    changed.update(bad, BLOCK);
    changed.update(GOLDEN_STREAM + BLOCK, sizeof GOLDEN_STREAM - BLOCK);
    ASSERT_ERR(Err::HASH_MISMATCH, changed.finish(m.streamSha, m.streamSize));
}

// #ota-design item 4, the same numbers as tests/test_kota.py (which proves the bound by simulation).
static void test_inplace_bound_matches_the_host()
{
    TEST_ASSERT_EQUAL_UINT32((2130000u >> 12) + (2130000u >> 14) + 19, inplaceMargin(2130000));
    TEST_ASSERT_TRUE(inplaceSafe(2130000, 3342336));  // Heltec V3, T-Beam 1W app slot
    TEST_ASSERT_TRUE(inplaceSafe(2130000, 2424832));  // LoRa32 app
    TEST_ASSERT_FALSE(inplaceSafe(2424832 - 4096, 2424832));
    uint32_t r = 262144;
    uint32_t p = r + BLOCK + inplaceMargin(r);
    TEST_ASSERT_TRUE(inplaceSafe(r, p));
    TEST_ASSERT_FALSE(inplaceSafe(r, p - 1));
    TEST_ASSERT_FALSE(inplaceSafe(0xFFFFFFFFu, 0xFFFFFFFFu)); // no overflow
}

// ---- SPEC-0003 #ota-local: the local installer, with a RAM flash -------------------------------

class RamFlash : public Flash
{
  public:
    uint32_t spare = 16384;
    uint8_t mem[16384];
    uint32_t written = 0;
    bool begun = false, ended = false, booted = false, aborted = false, failWrite = false;
    uint32_t spareSize() override { return spare; }
    bool begin(uint32_t size) override
    {
        begun = true;
        written = 0;
        return size <= spare;
    }
    bool write(const uint8_t *d, size_t n) override
    {
        if (failWrite || written + n > sizeof mem)
            return false;
        memcpy(mem + written, d, n);
        written += n;
        return true;
    }
    bool end() override { return ended = true; }
    bool setBoot() override { return booted = true; }
    void abort() override { aborted = true; }
};

struct Rig {
    RamFlash flash;
    Identity id;
    Installer *ins;
    uint32_t now = 1000;
    Rig(uint16_t board = 1, uint32_t release = 4, bool trustTestKey = true)
    {
        id.boardId = board;
        id.env = "heltec-v3";
        id.release = release;
        if (trustTestKey) {
            id.keys[0] = PUB;
            id.keyCount = 1;
        }
        ins = new Installer(flash, id);
    }
    ~Rig() { delete ins; }
    Reply send(const uint8_t *f, size_t n)
    {
        return radioSrc ? ins->handleRadio(radioSrc, f, n, now++) : ins->handle(f, n, now++);
    }
    Reply manifest(const uint8_t *man, size_t len)
    {
        uint8_t f[233];
        Reply r = Reply::NONE;
        for (size_t off = 0; off < len;) {
            size_t n = len - off < 200 ? len - off : 200;
            f[0] = L_MANIFEST;
            f[1] = off & 0xff;
            f[2] = off >> 8;
            f[3] = len & 0xff;
            f[4] = len >> 8;
            memcpy(f + 5, man + off, n);
            r = send(f, 5 + n);
            off += n;
        }
        return r;
    }
    Reply blockList(const uint8_t *list, size_t len)
    {
        uint8_t f[233];
        Reply r = Reply::NONE;
        for (size_t off = 0; off < len;) {
            size_t n = len - off < 224 ? len - off : 224;
            f[0] = L_LIST;
            for (int i = 0; i < 4; i++)
                f[1 + i] = (uint8_t)(off >> (8 * i));
            memcpy(f + 5, list + off, n);
            r = send(f, 5 + n);
            off += n;
        }
        return r;
    }
    // Sends block idx of data; skip >= 0 drops that frame. Returns the last reply.
    Reply block(uint16_t idx, const uint8_t *data, int skip = -1)
    {
        uint32_t len = blockLength(GOLDEN_RAW_SIZE, idx);
        uint8_t f[233];
        Reply r = Reply::NONE;
        int k = 0;
        for (uint32_t off = 0; off < len; off += DATA_MAX, k++) {
            uint32_t n = len - off < DATA_MAX ? len - off : DATA_MAX;
            f[0] = L_DATA;
            f[1] = idx & 0xff;
            f[2] = idx >> 8;
            f[3] = off & 0xff;
            f[4] = off >> 8;
            memcpy(f + 5, data + off, n);
            if (k != skip) {
                Reply x = send(f, 5 + n);
                if (x != Reply::NONE)
                    r = x; // the reply the client would wait for
            }
        }
        return r;
    }
    uint32_t radioSrc = 0; // not 0: send() goes in as a frame broadcast by that node (K2a)
    uint8_t lastBlockResult()
    {
        uint8_t b[8];
        TEST_ASSERT_EQUAL_UINT(4, ins->encodeBlock(b, sizeof b));
        return b[3];
    }
    Reply finish(uint8_t reboot = 1)
    {
        uint8_t f[2] = {L_FINISH, reboot};
        return send(f, 2);
    }
    void toData()
    {
        TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST));
        TEST_ASSERT_EQUAL_INT((int)State::LIST, (int)ins->state());
        TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)blockList(GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS));
        TEST_ASSERT_EQUAL_INT((int)State::DATA, (int)ins->state());
    }
};

#define ASSERT_STATE(rig, s) TEST_ASSERT_EQUAL_INT((int)(s), (int)(rig).ins->state())

static void test_local_install_happy_path()
{
    Rig r;
    r.toData();
    for (uint16_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(i, GOLDEN_RAW + i * BLOCK));
        TEST_ASSERT_EQUAL_UINT8(0, r.lastBlockResult());
    }
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.finish());
    ASSERT_STATE(r, State::DONE);
    TEST_ASSERT_TRUE(r.flash.ended && r.flash.booted && r.ins->rebootRequested());
    TEST_ASSERT_EQUAL_UINT32(GOLDEN_RAW_SIZE, r.flash.written);
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, r.flash.mem, GOLDEN_RAW_SIZE);

    PlatformStatus ps;
    ps.version = "2.7.26.abc";
    uint8_t st[64];
    size_t n = r.ins->encodeStatus(ps, st, sizeof st);
    TEST_ASSERT_EQUAL_UINT(27 + 10 + 1 + 9, n); // 27 fixed bytes (SPEC-0003 #ota-local), the version, the env (U1)
    TEST_ASSERT_EQUAL_UINT8(9, st[37]);
    TEST_ASSERT_EQUAL_MEMORY("heltec-v3", st + 38, 9);
    TEST_ASSERT_EQUAL_UINT8(L_STATUS, st[0]);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)State::DONE, st[1]);
    TEST_ASSERT_EQUAL_UINT8(3, st[3]); // next block
    TEST_ASSERT_EQUAL_UINT8(3, st[5]); // blocks
}

// Acceptance 1 on the installer: nothing is written and the boot slot is not touched.
static void test_local_refusals_touch_no_flash()
{
    {
        Rig r;
        uint8_t bad[sizeof GOLDEN_MANIFEST];
        memcpy(bad, GOLDEN_MANIFEST, sizeof bad);
        bad[sizeof bad - 1] ^= 1;
        r.manifest(bad, sizeof bad);
        ASSERT_STATE(r, State::FAILED);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::SIGNATURE, r.ins->error());
        TEST_ASSERT_FALSE(r.flash.begun || r.flash.booted);
    }
    {
        Rig r(1, 4, false); // a build that trusts only the release key
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::UNKNOWN_KEY, r.ins->error());
    }
    {
        Rig r(3, 4);
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::BOARD, r.ins->error());
    }
    {
        Rig r(1, 5);
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::NOT_NEWER, r.ins->error());
    }
    {
        Rig r;
        r.flash.spare = 8192;
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::SLOT, r.ins->error());
        TEST_ASSERT_FALSE(r.flash.begun);
    }
    {
        Rig r;
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        uint8_t list[sizeof GOLDEN_RAW_BLOCKS];
        memcpy(list, GOLDEN_RAW_BLOCKS, sizeof list);
        list[5] ^= 1;
        r.blockList(list, sizeof list);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::BLOCK_LIST, r.ins->error());
        TEST_ASSERT_FALSE(r.flash.begun);
    }
}

static void test_local_bad_block_is_not_written_and_can_be_resent()
{
    Rig r;
    r.toData();
    static uint8_t bad[BLOCK];
    memcpy(bad, GOLDEN_RAW, BLOCK);
    bad[1000] ^= 0x10;
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, bad));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::HASH_MISMATCH, r.lastBlockResult());
    TEST_ASSERT_EQUAL_UINT32(0, r.flash.written);
    TEST_ASSERT_EQUAL_UINT32(0, r.ins->nextBlock());
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, GOLDEN_RAW));
    TEST_ASSERT_EQUAL_UINT8(0, r.lastBlockResult());
    TEST_ASSERT_EQUAL_UINT32(BLOCK, r.flash.written);
}

static void test_local_lost_frame_and_duplicate_block()
{
    Rig r;
    r.toData();
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.block(0, GOLDEN_RAW, 3)); // frame 3 lost: no reply
    TEST_ASSERT_EQUAL_UINT32(0, r.flash.written);
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, GOLDEN_RAW)); // resent from its start
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, GOLDEN_RAW)); // a duplicate: acknowledged again
    TEST_ASSERT_EQUAL_UINT8(0, r.lastBlockResult());
    TEST_ASSERT_EQUAL_UINT32(BLOCK, r.flash.written);
    TEST_ASSERT_EQUAL_UINT32(1, r.ins->nextBlock());
}

// K2a: the same frames broadcast over LoRa, with losses, bystanders and a second sender.
static void test_radio_install_with_losses()
{
    Rig r;
    r.radioSrc = 0x1b9dc120;
    r.toData();
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST));
    ASSERT_STATE(r, State::DATA); // the same manifest keeps the session
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.blockList(GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS));
    ASSERT_STATE(r, State::DATA); // a list resent after it is complete is answered, not an error
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.block(0, GOLDEN_RAW, 3)); // a lost frame
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, GOLDEN_RAW));
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.finish()); // early: refused, the session goes on
    ASSERT_STATE(r, State::DATA);
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(1, GOLDEN_RAW + BLOCK));
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(0, GOLDEN_RAW)); // resent for another node
    TEST_ASSERT_EQUAL_INT((int)Reply::BLOCK, (int)r.block(2, GOLDEN_RAW + 2 * BLOCK));
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.finish());
    ASSERT_STATE(r, State::DONE);
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.finish()); // its answer was lost: asked again
    ASSERT_STATE(r, State::DONE);
    TEST_ASSERT_TRUE(r.flash.booted && r.ins->rebootRequested());
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, r.flash.mem, GOLDEN_RAW_SIZE);
}

static void test_radio_duplicate_block_is_acked_once()
{
    Rig r;
    r.radioSrc = 7;
    r.toData();
    r.block(0, GOLDEN_RAW);
    uint8_t f[5 + DATA_MAX] = {L_DATA, 0, 0, 0, 0};
    memcpy(f + 5, GOLDEN_RAW, DATA_MAX);
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.send(f, sizeof f)); // not while the rest is on the air
}

static void test_radio_list_out_of_order_and_stray_frames_are_silent()
{
    Rig r;
    r.radioSrc = 7;
    uint8_t l[5 + 32] = {L_LIST, 0, 0, 0, 0};
    memcpy(l + 5, GOLDEN_RAW_BLOCKS, 32);
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.send(l, sizeof l)); // no session here
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.finish());
    ASSERT_STATE(r, State::IDLE);
    r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    l[1] = 32; // the first list frame was lost
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.send(l, sizeof l));
    ASSERT_STATE(r, State::LIST);
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.blockList(GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS));
    ASSERT_STATE(r, State::DATA);
}

static void test_radio_one_session_one_source()
{
    Rig r;
    r.radioSrc = 7;
    r.toData();
    r.radioSrc = 8; // another sender
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST));
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.block(0, GOLDEN_RAW));
    r.radioSrc = 0; // a local client
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.block(0, GOLDEN_RAW));
    ASSERT_STATE(r, State::DATA);
    TEST_ASSERT_EQUAL_UINT32(0, r.flash.written);
    r.ins->tick(r.now + SESSION_TIMEOUT_MS + 10);
    ASSERT_STATE(r, State::DATA);
    r.ins->tick(r.now + RADIO_TIMEOUT_MS + 10);
    ASSERT_STATE(r, State::FAILED);

    Rig q;
    q.toData(); // a local session
    q.radioSrc = 7;
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)q.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST));
    ASSERT_STATE(q, State::DATA);
}

static void test_local_early_finish_timeout_and_restart()
{
    {
        Rig r;
        r.toData();
        r.block(0, GOLDEN_RAW);
        r.finish();
        ASSERT_STATE(r, State::FAILED);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::SEQUENCE, r.ins->error());
        TEST_ASSERT_TRUE(r.flash.aborted);
        TEST_ASSERT_FALSE(r.flash.booted);
    }
    {
        Rig r;
        r.toData();
        r.ins->tick(r.now + SESSION_TIMEOUT_MS - 10);
        ASSERT_STATE(r, State::DATA);
        r.ins->tick(r.now + SESSION_TIMEOUT_MS + 10);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::TIMEOUT, r.ins->error());
        TEST_ASSERT_TRUE(r.flash.aborted);
    }
    {
        Rig r;
        r.toData();
        r.block(0, GOLDEN_RAW);
        r.manifest(GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST); // a new session from offset 0
        TEST_ASSERT_TRUE(r.flash.aborted);
        ASSERT_STATE(r, State::LIST);
        TEST_ASSERT_EQUAL_UINT32(0, r.ins->nextBlock());
    }
    {
        Rig r;
        r.toData();
        r.flash.failWrite = true;
        r.block(0, GOLDEN_RAW);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::FLASH, r.ins->error());
        TEST_ASSERT_FALSE(r.flash.booted);
    }
}

static void test_local_ignores_mesh_types_and_stray_data()
{
    Rig r;
    const uint8_t mesh[] = {0x03, 1, 2, 3};
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.send(mesh, sizeof mesh));
    const uint8_t data[] = {L_DATA, 0, 0, 0, 0, 9};
    TEST_ASSERT_EQUAL_INT((int)Reply::NONE, (int)r.send(data, sizeof data));
    ASSERT_STATE(r, State::IDLE);
    const uint8_t q[] = {L_QUERY};
    TEST_ASSERT_EQUAL_INT((int)Reply::STATUS, (int)r.send(q, 1));
}

// ---- SPEC-0003 #ota-updater (U1): the sender on the node, the library, the codecs -------------

class MemSource : public ImageSource
{
  public:
    bool corrupt = false;
    size_t manifest(uint8_t *out, size_t max) override
    {
        if (max < sizeof GOLDEN_MANIFEST)
            return 0;
        memcpy(out, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
        return sizeof GOLDEN_MANIFEST;
    }
    uint32_t listSize() override { return sizeof GOLDEN_RAW_BLOCKS; }
    bool readList(uint32_t off, uint8_t *out, size_t n) override
    {
        if (off + n > sizeof GOLDEN_RAW_BLOCKS)
            return false;
        memcpy(out, GOLDEN_RAW_BLOCKS + off, n);
        return true;
    }
    uint32_t rawSize() override { return GOLDEN_RAW_SIZE; }
    bool readRaw(uint32_t off, uint8_t *out, size_t n) override
    {
        if (off + n > GOLDEN_RAW_SIZE)
            return false;
        memcpy(out, GOLDEN_RAW + off, n);
        if (corrupt && off <= 5000 && 5000 < off + n)
            out[5000 - off] ^= 1;
        return true;
    }
};

// Receivers are real Installers. A frame or a reply is lost with probability lossPermille.
struct Air : public RadioOut {
    static constexpr uint32_t ME = 0xA0A0A0A0;
    struct Rx {
        uint32_t node;
        Rig *rig;
        bool silent;
        int dropStatus; // drop this many STATUS replies first
    } rx[4];
    size_t nrx = 0;
    uint32_t lossPermille = 0;
    uint32_t seed = 12345;
    uint32_t now = 1000;
    uint32_t frames = 0, dataFrames = 0;
    struct Q {
        uint32_t src;
        uint8_t b[100];
        size_t n;
    } q[64];
    size_t nq = 0;

    bool lost()
    {
        seed = seed * 1103515245u + 12345u;
        return ((seed >> 16) % 1000) < lossPermille;
    }
    void add(uint32_t node, Rig *r, bool silent = false, int dropStatus = 0)
    {
        rx[nrx++] = {node, r, silent, dropStatus};
    }
    bool ready() override { return true; }
    uint32_t airtimeMs(size_t n) override { return 5 + (uint32_t)n / 10; }
    bool send(const uint8_t *f, size_t n) override
    {
        frames++;
        if (f[0] == L_DATA)
            dataFrames++;
        for (size_t i = 0; i < nrx; i++) {
            if (rx[i].silent || lost())
                continue;
            Rig &r = *rx[i].rig;
            Reply rep = r.ins->handleRadio(ME, f, n, now);
            if (rep == Reply::NONE || lost())
                continue;
            if (rep == Reply::STATUS && rx[i].dropStatus > 0) {
                rx[i].dropStatus--;
                continue;
            }
            if (nq >= 64)
                continue;
            Q &e = q[nq++];
            e.src = rx[i].node;
            if (rep == Reply::BLOCK) {
                e.n = r.ins->encodeBlock(e.b, sizeof e.b);
            } else {
                PlatformStatus ps;
                ps.version = "2.7.26.test";
                e.n = r.ins->encodeStatus(ps, e.b, sizeof e.b);
            }
        }
        return true;
    }
    // Run the sender until it stops; replies arrive between its steps.
    void run(Sender &s, uint32_t limitMs = 20000000)
    {
        uint32_t end = now + limitMs;
        while (s.busy() && (int32_t)(now - end) < 0) {
            uint32_t w = s.step(now);
            for (size_t i = 0; i < nq; i++)
                s.onReply(q[i].src, q[i].b, q[i].n, -40, 40, now);
            nq = 0;
            now += w ? (w < 200 ? w : 200) : 1;
        }
    }
};

static SenderConfig fastCfg()
{
    SenderConfig c;
    c.retries = 30;
    c.blockTimeoutMs = 500;
    c.queryTimeoutMs = 5000;
    return c;
}

static void test_sender_installs_two_targets_with_one_transmission()
{
    Rig a, b;
    Air air;
    air.add(1, &a);
    air.add(2, &b);
    MemSource src;
    Sender s(air);
    uint32_t nodes[2] = {1, 2};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 2, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::DONE, (int)s.phase());
    ASSERT_STATE(a, State::DONE);
    ASSERT_STATE(b, State::DONE);
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, a.flash.mem, GOLDEN_RAW_SIZE);
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, b.flash.mem, GOLDEN_RAW_SIZE);
    uint32_t perImage = 0;
    for (uint32_t i = 0; i < 3; i++)
        perImage += (blockLength(GOLDEN_RAW_SIZE, i) + DATA_MAX - 1) / DATA_MAX;
    TEST_ASSERT_EQUAL_UINT32(perImage, air.dataFrames); // acceptance 6 without loss: once for both
    TEST_ASSERT_EQUAL_UINT32(0, s.resent());
}

static void test_sender_with_losses_still_installs()
{
    for (uint32_t seed = 1; seed <= 5; seed++) {
        Rig a, b;
        Air air;
        air.seed = seed;
        air.lossPermille = 100;
        air.add(1, &a);
        air.add(2, &b);
        MemSource src;
        Sender s(air);
        uint32_t nodes[2] = {1, 2};
        TEST_ASSERT_TRUE(s.push(&src, nodes, 2, fastCfg(), air.now));
        air.run(s);
        TEST_ASSERT_EQUAL_INT_MESSAGE((int)Phase::DONE, (int)s.phase(), "10 % loss");
        TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, a.flash.mem, GOLDEN_RAW_SIZE);
        TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, b.flash.mem, GOLDEN_RAW_SIZE);
    }
}

static void test_sender_asks_again_until_every_target_answered()
{
    Rig a, b;
    Air air;
    air.add(1, &a);
    air.add(2, &b, false, 1); // the first STATUS of node 2 is lost (CF-lora-query-*.txt)
    MemSource src;
    Sender s(air);
    uint32_t nodes[2] = {1, 2};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 2, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::DONE, (int)s.phase());
}

static void test_sender_silent_target_fails_with_no_answer()
{
    Rig a, b;
    Air air;
    air.add(1, &a);
    air.add(2, &b, true);
    MemSource src;
    Sender s(air);
    uint32_t nodes[2] = {1, 2};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 2, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::FAILED, (int)s.phase());
    TEST_ASSERT_EQUAL_INT((int)Why::NO_ANSWER, (int)s.why());
    ASSERT_STATE(a, State::IDLE); // nothing was sent to anyone
}

static void test_sender_wrong_board_target_fails_the_push()
{
    Rig a(2); // a LoRa32 is offered a Heltec image
    Air air;
    air.add(1, &a);
    MemSource src;
    Sender s(air);
    uint32_t nodes[1] = {1};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 1, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::FAILED, (int)s.phase());
    TEST_ASSERT_EQUAL_INT((int)Why::TARGET_FAILED, (int)s.why());
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::BOARD, s.target(0).err);
}

static void test_sender_refuses_an_image_the_card_changed()
{
    Rig a;
    Air air;
    air.add(1, &a);
    MemSource src;
    src.corrupt = true;
    Sender s(air);
    uint32_t nodes[1] = {1};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 1, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Why::IMAGE_HASH, (int)s.why());
    TEST_ASSERT_EQUAL_UINT32(0, air.frames); // checked before anything goes on the air
}

static void test_sender_resumes_where_the_targets_are()
{
    Rig a;
    a.radioSrc = Air::ME;
    a.toData();
    a.block(0, GOLDEN_RAW);
    a.block(1, GOLDEN_RAW + BLOCK); // a sender that stopped after block 1
    Air air;
    air.add(1, &a);
    MemSource src;
    Sender s(air);
    uint32_t nodes[1] = {1};
    TEST_ASSERT_TRUE(s.push(&src, nodes, 1, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::DONE, (int)s.phase());
    TEST_ASSERT_EQUAL_UINT32((blockLength(GOLDEN_RAW_SIZE, 2) + DATA_MAX - 1) / DATA_MAX, air.dataFrames);
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, a.flash.mem, GOLDEN_RAW_SIZE);
}

static void test_scan_lists_every_node_that_answers_with_its_env()
{
    Rig a, b(2);
    Air air;
    air.add(0x1b9dc120, &a);
    air.add(0x1c15d508, &b);
    Sender s(air);
    TEST_ASSERT_TRUE(s.scan(3, 1000, air.now));
    TEST_ASSERT_FALSE(s.scan(3, 1000, air.now)); // busy
    air.run(s);
    TEST_ASSERT_EQUAL_UINT(2, s.heardCount());
    const Heard &h = s.heard(0).node == 0x1b9dc120 ? s.heard(0) : s.heard(1);
    TEST_ASSERT_EQUAL_UINT16(1, h.board);
    TEST_ASSERT_EQUAL_UINT32(4, h.release);
    TEST_ASSERT_EQUAL_STRING("heltec-v3", h.env);
    TEST_ASSERT_EQUAL_STRING("2.7.26.test", h.version);
    uint8_t o[160];
    size_t n = encodeNode(s, 0, air.now, o, sizeof o);
    TEST_ASSERT_EQUAL_UINT8(U_NODE, o[0]);
    TEST_ASSERT_EQUAL_UINT8(2, o[2]);
    TEST_ASSERT_EQUAL_UINT(13 + s.heard(0).rawLen, n);
    TEST_ASSERT_EQUAL_UINT8(L_STATUS, o[13]);
}

static void test_status_without_env_still_parses()
{
    uint8_t b[27 + 3] = {L_STATUS};
    b[26] = 3;
    memcpy(b + 27, "1.0", 3);
    Heard h;
    TEST_ASSERT_TRUE(parseStatus(b, sizeof b, h));
    TEST_ASSERT_EQUAL_STRING("1.0", h.version);
    TEST_ASSERT_EQUAL_STRING("", h.env);
    TEST_ASSERT_FALSE(parseStatus(b, 20, h));
}

// A card in RAM: /koldnet/lib/<dir>/{manifest.bin, raw.blocks, raw.bin}.
struct MemStorage : public Storage {
    struct F {
        char path[80];
        const uint8_t *data;
        int32_t len;
    } f[16];
    size_t nf = 0;
    const char *dirs[8];
    size_t nd = 0;
    void file(const char *dir, const char *name, const uint8_t *d, int32_t len)
    {
        snprintf(f[nf].path, sizeof f[nf].path, "/koldnet/lib/%s/%s", dir, name);
        f[nf].data = d;
        f[nf++].len = len;
    }
    void image(const char *dir, const uint8_t *man, int32_t manLen, int32_t rawLen = GOLDEN_RAW_SIZE)
    {
        dirs[nd++] = dir;
        file(dir, "manifest.bin", man, manLen);
        file(dir, "raw.blocks", GOLDEN_RAW_BLOCKS, sizeof GOLDEN_RAW_BLOCKS);
        file(dir, "raw.bin", GOLDEN_RAW, rawLen);
    }
    size_t listDirs(const char *path, char (*names)[LIB_NAME], size_t max) override
    {
        size_t n = 0;
        for (; n < nd && n < max; n++)
            strncpy(names[n], dirs[n], LIB_NAME);
        return n;
    }
    const F *find(const char *p)
    {
        for (size_t i = 0; i < nf; i++)
            if (!strcmp(f[i].path, p))
                return &f[i];
        return nullptr;
    }
    int32_t size(const char *p) override
    {
        const F *x = find(p);
        return x ? x->len : -1;
    }
    bool read(const char *p, uint32_t off, uint8_t *buf, size_t n) override
    {
        const F *x = find(p);
        if (!x || off + n > (uint32_t)x->len)
            return false;
        memcpy(buf, x->data + off, n);
        return true;
    }
};

static void test_library_verifies_every_image_on_the_card()
{
    static uint8_t badSig[sizeof GOLDEN_MANIFEST];
    memcpy(badSig, GOLDEN_MANIFEST, sizeof badSig);
    badSig[sizeof badSig - 1] ^= 1;
    MemStorage card;
    card.image("heltec-v3-r5", GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    card.image("tampered", badSig, sizeof badSig);
    card.image("short-raw", GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, GOLDEN_RAW_SIZE - 1);
    card.dirs[card.nd++] = "empty";
    Library lib;
    const uint8_t *keys[1] = {PUB};
    TEST_ASSERT_EQUAL_UINT(4, lib.scan(card, keys, 1));
    TEST_ASSERT_EQUAL_UINT8(0, lib.entry(0).err);
    TEST_ASSERT_EQUAL_STRING("heltec-v3", lib.entry(0).m.env);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::SIGNATURE, lib.entry(1).err);
    TEST_ASSERT_EQUAL_UINT8(LIB_RAW_SIZE, lib.entry(2).err);
    TEST_ASSERT_EQUAL_UINT8(LIB_NO_MANIFEST, lib.entry(3).err);
    uint8_t other[32];
    memcpy(other, PUB, 32);
    other[0] ^= 1;
    const uint8_t *wrong[1] = {other};
    lib.scan(card, wrong, 1);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::KEY_ID, lib.entry(0).err);

    lib.scan(card, keys, 1);
    uint8_t o[160];
    size_t n = encodeLibEntry(lib, 0, o, sizeof o);
    TEST_ASSERT_EQUAL_UINT8(U_LIBENT, o[0]);
    TEST_ASSERT_EQUAL_UINT8(4, o[2]);
    TEST_ASSERT_EQUAL_UINT8(5, o[6]); // release
    TEST_ASSERT_EQUAL_UINT(15 + 1 + 9 + 1 + 14 + 1 + 12, n);

    // The library entry is what the sender sends.
    LibSource ls(card, lib.entry(0));
    Rig a;
    Air air;
    air.add(1, &a);
    Sender s(air);
    uint32_t nodes[1] = {1};
    TEST_ASSERT_TRUE(s.push(&ls, nodes, 1, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::DONE, (int)s.phase());
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, a.flash.mem, GOLDEN_RAW_SIZE);
}

static void test_library_fits_board_env_and_release()
{
    MemStorage card;
    card.image("heltec-v3-r5", GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST);
    Library lib;
    const uint8_t *keys[1] = {PUB};
    lib.scan(card, keys, 1);
    Heard h;
    h.board = 1;
    h.release = 4;
    strcpy(h.env, "heltec-v3");
    TEST_ASSERT_TRUE(lib.fits(0, h));
    strcpy(h.env, "heltec-v3-koldnet-ap"); // E: the same board, another env
    TEST_ASSERT_FALSE(lib.fits(0, h));
    h.env[0] = 0; // a build before U1 says no env: the board decides, the target checks the env
    TEST_ASSERT_TRUE(lib.fits(0, h));
    h.release = 5;
    TEST_ASSERT_FALSE(lib.fits(0, h));
    h.release = 4;
    h.board = 2;
    TEST_ASSERT_FALSE(lib.fits(0, h));
    TEST_ASSERT_FALSE(lib.fits(1, h)); // no such entry
}

static void test_progress_frame()
{
    Rig a;
    Air air;
    air.add(1, &a);
    MemSource src;
    Sender s(air);
    uint32_t nodes[1] = {1};
    s.push(&src, nodes, 1, fastCfg(), air.now);
    air.run(s);
    uint8_t o[100];
    size_t n = s.encodeProgress(air.now, o, sizeof o);
    TEST_ASSERT_EQUAL_UINT(14 + 8, n);
    TEST_ASSERT_EQUAL_UINT8(U_PROG, o[0]);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Phase::DONE, o[1]);
    TEST_ASSERT_EQUAL_UINT8(3, o[6]); // of 3 blocks
    TEST_ASSERT_EQUAL_UINT8(1, o[14]);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)State::DONE, o[18]);
}

static bool goldenRaw(uint32_t off, uint8_t *out, size_t n)
{
    if (off + n > GOLDEN_RAW_SIZE)
        return false;
    memcpy(out, GOLDEN_RAW + off, n);
    return true;
}

static void test_own_image_is_uploaded_checked_and_sent()
{
    const uint8_t *keys[1] = {PUB};
    SelfSource me(goldenRaw);
    TEST_ASSERT_EQUAL_UINT8(0, me.put(0, 0, GOLDEN_MANIFEST, 200, keys, 1));
    TEST_ASSERT_FALSE(me.complete());
    TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::SEQUENCE, me.put(1, 0, GOLDEN_RAW_BLOCKS, 32, keys, 1)); // before the manifest
    TEST_ASSERT_EQUAL_UINT8(0, me.put(0, 200, GOLDEN_MANIFEST + 200, sizeof GOLDEN_MANIFEST - 200, keys, 1));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::SEQUENCE, me.put(1, 32, GOLDEN_RAW_BLOCKS + 32, 32, keys, 1)); // out of order
    uint8_t bad[sizeof GOLDEN_RAW_BLOCKS];
    memcpy(bad, GOLDEN_RAW_BLOCKS, sizeof bad);
    bad[40] ^= 1;
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Err::BLOCK_LIST, me.put(1, 0, bad, sizeof bad, keys, 1));
    TEST_ASSERT_FALSE(me.complete());
    TEST_ASSERT_EQUAL_UINT8(0, me.put(1, 0, GOLDEN_RAW_BLOCKS, 64, keys, 1));
    TEST_ASSERT_EQUAL_UINT8(0, me.put(1, 64, GOLDEN_RAW_BLOCKS + 64, 32, keys, 1));
    TEST_ASSERT_TRUE(me.complete());

    Rig a;
    Air air;
    air.add(1, &a);
    Sender s(air);
    uint32_t nodes[1] = {1};
    TEST_ASSERT_TRUE(s.push(&me, nodes, 1, fastCfg(), air.now));
    air.run(s);
    TEST_ASSERT_EQUAL_INT((int)Phase::DONE, (int)s.phase());
    TEST_ASSERT_EQUAL_MEMORY(GOLDEN_RAW, a.flash.mem, GOLDEN_RAW_SIZE);

    uint8_t other[32];
    memcpy(other, PUB, 32);
    other[0] ^= 1;
    const uint8_t *wrong[1] = {other};
    SelfSource you(goldenRaw);
    you.put(0, 0, GOLDEN_MANIFEST, sizeof GOLDEN_MANIFEST, wrong, 1);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)LErr::SEQUENCE, you.put(1, 0, GOLDEN_RAW_BLOCKS, 32, wrong, 1)); // never verified
    TEST_ASSERT_FALSE(you.complete());
}

void setup()
{
    initializeTestEnvironment();
    derive_test_key();
    UNITY_BEGIN();
    RUN_TEST(test_golden_manifest_verifies_and_parses);
    RUN_TEST(test_any_changed_byte_fails_the_signature);
    RUN_TEST(test_other_key_is_refused_by_key_id);
    RUN_TEST(test_install_rules);
    RUN_TEST(test_malformed_manifests_are_refused_before_the_signature);
    RUN_TEST(test_block_lists_and_blocks);
    RUN_TEST(test_inplace_bound_matches_the_host);
    RUN_TEST(test_local_install_happy_path);
    RUN_TEST(test_local_refusals_touch_no_flash);
    RUN_TEST(test_local_bad_block_is_not_written_and_can_be_resent);
    RUN_TEST(test_local_lost_frame_and_duplicate_block);
    RUN_TEST(test_local_early_finish_timeout_and_restart);
    RUN_TEST(test_radio_install_with_losses);
    RUN_TEST(test_radio_duplicate_block_is_acked_once);
    RUN_TEST(test_radio_list_out_of_order_and_stray_frames_are_silent);
    RUN_TEST(test_radio_one_session_one_source);
    RUN_TEST(test_local_ignores_mesh_types_and_stray_data);
    RUN_TEST(test_sender_installs_two_targets_with_one_transmission);
    RUN_TEST(test_sender_with_losses_still_installs);
    RUN_TEST(test_sender_asks_again_until_every_target_answered);
    RUN_TEST(test_sender_silent_target_fails_with_no_answer);
    RUN_TEST(test_sender_wrong_board_target_fails_the_push);
    RUN_TEST(test_sender_refuses_an_image_the_card_changed);
    RUN_TEST(test_sender_resumes_where_the_targets_are);
    RUN_TEST(test_scan_lists_every_node_that_answers_with_its_env);
    RUN_TEST(test_status_without_env_still_parses);
    RUN_TEST(test_library_verifies_every_image_on_the_card);
    RUN_TEST(test_library_fits_board_env_and_release);
    RUN_TEST(test_progress_frame);
    RUN_TEST(test_own_image_is_uploaded_checked_and_sent);
    exit(UNITY_END());
}

void loop() {}
