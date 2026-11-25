// koldnet SPEC-0003 #ota-format: the signed manifest, block lists, install rules and the in-place
// bound, on the host. The vectors come from scripts/kota.py in koldnet (vectors.h, generated), and
// are signed with a throwaway test key derived from KOTA_TEST_SEED_TEXT, never a release key.
#include "TestUtil.h"
#include "configuration.h" // Arduino.h: setup() and loop() with C linkage
#include "mesh/koldnet/KotaImage.h"
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
    exit(UNITY_END());
}

void loop() {}
