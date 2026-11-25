#include "KotaImage.h"

#include <Ed25519.h>
#include <string.h>

namespace kota
{

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[HASH])
{
    SHA256 h;
    h.update(data, len);
    h.finalize(out, HASH);
}

static bool equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0; // constant time; the values are not secret, but it costs nothing
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

Err parse(const uint8_t *buf, size_t len, Manifest &m)
{
    if (!buf || len < MIN_MANIFEST || len > MAX_MANIFEST)
        return Err::LENGTH;
    if (memcmp(buf, "KOTA", 4) != 0 || buf[4] != FORMAT)
        return Err::MAGIC;
    m.flags = buf[5];
    if (m.flags & ~FLAG_DOWNGRADE)
        return Err::FLAG;
    m.boardId = le16(buf + 6);
    m.release = le32(buf + 8);
    m.keyId = le32(buf + 12);
    m.rawSize = le32(buf + 16);
    memcpy(m.rawSha, buf + 20, HASH);
    m.streamSize = le32(buf + 52);
    memcpy(m.streamSha, buf + 56, HASH);
    memcpy(m.rawListSha, buf + 88, HASH);
    memcpy(m.streamListSha, buf + 120, HASH);
    if (m.rawSize == 0 || m.streamSize == 0)
        return Err::EMPTY;
    size_t o = HEAD;
    size_t n = buf[o];
    if (n < 1 || n > MAX_STR || o + 1 + n >= len)
        return Err::ENV_LENGTH;
    memcpy(m.env, buf + o + 1, n);
    m.env[n] = 0;
    o += 1 + n;
    size_t v = buf[o];
    if (v < 1 || v > MAX_STR || o + 1 + v + SIG != len)
        return Err::VERSION_LENGTH;
    memcpy(m.version, buf + o + 1, v);
    m.version[v] = 0;
    if (strlen(m.env) != n || strlen(m.version) != v) // an embedded NUL would let two strings compare equal
        return Err::ENV_LENGTH;
    memcpy(m.signature, buf + len - SIG, SIG);
    return Err::OK;
}

uint32_t keyId(const uint8_t publicKey[32])
{
    uint8_t h[HASH];
    sha256(publicKey, 32, h);
    return le32(h);
}

Err verify(const uint8_t *buf, size_t len, const uint8_t publicKey[32], Manifest &m)
{
    Err e = parse(buf, len, m);
    if (e != Err::OK)
        return e;
    if (m.keyId != keyId(publicKey))
        return Err::KEY_ID;
    if (!Ed25519::verify(m.signature, publicKey, buf, len - SIG))
        return Err::SIGNATURE;
    return Err::OK;
}

Err checkInstall(const Manifest &m, uint16_t boardId, const char *env, uint32_t release)
{
    if (m.boardId != boardId)
        return Err::BOARD;
    if (!env || strcmp(m.env, env) != 0)
        return Err::ENV;
    if (m.release <= release && !(m.flags & FLAG_DOWNGRADE))
        return Err::NOT_NEWER;
    return Err::OK;
}

uint32_t blockCount(uint32_t size)
{
    return (uint32_t)(((uint64_t)size + BLOCK - 1) / BLOCK);
}

uint32_t blockLength(uint32_t size, uint32_t index)
{
    uint32_t count = blockCount(size);
    if (index >= count)
        return 0;
    return index + 1 < count ? BLOCK : size - index * BLOCK;
}

Err checkBlockList(const uint8_t listSha[HASH], uint32_t size, const uint8_t *list, size_t len)
{
    if (!list || len != (size_t)blockCount(size) * HASH)
        return Err::SIZE;
    uint8_t h[HASH];
    sha256(list, len, h);
    return equal(h, listSha, HASH) ? Err::OK : Err::BLOCK_LIST;
}

Err checkBlock(const uint8_t *list, uint32_t size, uint32_t index, const uint8_t *data, size_t len)
{
    if (index >= blockCount(size))
        return Err::BLOCK_INDEX;
    if (!data || len != blockLength(size, index))
        return Err::SIZE;
    uint8_t h[HASH];
    sha256(data, len, h);
    return equal(h, list + (size_t)index * HASH, HASH) ? Err::OK : Err::HASH_MISMATCH;
}

void ObjectHash::update(const uint8_t *data, size_t len)
{
    h.update(data, len);
    n += (uint32_t)len;
}

Err ObjectHash::finish(const uint8_t expectedSha[HASH], uint32_t expectedSize)
{
    uint8_t out[HASH];
    h.finalize(out, HASH);
    if (n != expectedSize)
        return Err::SIZE;
    return equal(out, expectedSha, HASH) ? Err::OK : Err::HASH_MISMATCH;
}

uint32_t inplaceMargin(uint32_t r)
{
    return (r >> 12) + (r >> 14) + (r >> 25) + 19;
}

bool inplaceSafe(uint32_t rawSize, uint32_t slotSize)
{
    return (uint64_t)rawSize + BLOCK + inplaceMargin(rawSize) <= slotSize;
}

} // namespace kota
