#pragma once
// koldnet OTA image format (SPEC-0003 #ota-format): the signed manifest, block lists, the install
// rules and the in-place inflate bound. Pure logic: no flash, radio or Arduino include, so it is
// tested on the host (test/test_kota) against golden vectors from scripts/kota.py in koldnet.
// The transfer (KOTA port 333) and the flash glue are later phases (SPEC-0003 #plan K1, K2).

#include <SHA256.h>
#include <stddef.h>
#include <stdint.h>

namespace kota
{

constexpr uint8_t FORMAT = 1;
constexpr uint8_t FLAG_DOWNGRADE = 0x01;
constexpr uint32_t BLOCK = 4096;
constexpr size_t HASH = 32;
constexpr size_t HEAD = 152; // through the stream block-list hash
constexpr size_t SIG = 64;
constexpr size_t MAX_STR = 32;
constexpr size_t MIN_MANIFEST = HEAD + 1 + 1 + 1 + 1 + SIG;
constexpr size_t MAX_MANIFEST = HEAD + 1 + MAX_STR + 1 + MAX_STR + SIG; // 282

enum class Err : uint8_t {
    OK = 0,
    LENGTH,
    MAGIC,
    FLAG,
    EMPTY,
    ENV_LENGTH,
    VERSION_LENGTH,
    KEY_ID,
    SIGNATURE,
    BOARD,
    ENV,
    NOT_NEWER,
    SIZE,
    HASH_MISMATCH,
    BLOCK_LIST,
    BLOCK_INDEX,
};

struct Manifest {
    uint8_t flags = 0;
    uint16_t boardId = 0;
    uint32_t release = 0;
    uint32_t keyId = 0;
    uint32_t rawSize = 0;
    uint8_t rawSha[HASH] = {};
    uint32_t streamSize = 0;
    uint8_t streamSha[HASH] = {};
    uint8_t rawListSha[HASH] = {};
    uint8_t streamListSha[HASH] = {};
    char env[MAX_STR + 1] = {};
    char version[MAX_STR + 1] = {};
    uint8_t signature[SIG] = {};
};

/// Parse the layout only; checks lengths, magic, format, flags and sizes, not the signature.
Err parse(const uint8_t *buf, size_t len, Manifest &out);

/// The first 4 bytes of SHA-256 of the public key, little-endian.
uint32_t keyId(const uint8_t publicKey[32]);

/// parse(), then the key id and the Ed25519 signature over everything before it.
/// This is all a node checks before it caches and serves an image.
Err verify(const uint8_t *buf, size_t len, const uint8_t publicKey[32], Manifest &out);

/// The install rules: same board id and env, and a higher release unless the downgrade flag is set.
Err checkInstall(const Manifest &m, uint16_t boardId, const char *env, uint32_t release);

uint32_t blockCount(uint32_t objectSize);
uint32_t blockLength(uint32_t objectSize, uint32_t index);

/// A block list (32 bytes a block) against its hash in the manifest.
Err checkBlockList(const uint8_t listSha[HASH], uint32_t objectSize, const uint8_t *list, size_t len);

/// One received block against its entry in a checked block list.
Err checkBlock(const uint8_t *list, uint32_t objectSize, uint32_t index, const uint8_t *data, size_t len);

/// A whole object (raw image or stream) hashed as it is read, then compared with the manifest.
class ObjectHash
{
  public:
    void update(const uint8_t *data, size_t len);
    Err finish(const uint8_t expectedSha[HASH], uint32_t expectedSize);

  private:
    SHA256 h;
    uint32_t n = 0;
};

/// E(R): zlib's deflateBound margin plus the 6-byte header and Adler-32.
uint32_t inplaceMargin(uint32_t rawSize);
/// The stream at the end of a slot can be inflated into its start: R + 4096 + E(R) <= P.
bool inplaceSafe(uint32_t rawSize, uint32_t slotSize);

} // namespace kota
