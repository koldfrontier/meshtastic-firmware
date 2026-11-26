#pragma once
// koldnet field updater (SPEC-0003 #ota-updater, phase U1): the K2a sender on the node, the library of
// images on storage, and the local frames that control them. Pure logic: the radio and the storage are
// behind interfaces, so it is tested on the host (test/test_kota) against kota::Installer receivers.
// The ESP32 glue is in src/modules/KotaModule.cpp.

#include "KotaImage.h"
#include "KotaLocal.h"

namespace kota
{

constexpr size_t MAX_TARGETS = 8;
constexpr size_t MAX_HEARD = 24;
constexpr size_t STATUS_MAX = 100;
constexpr size_t LIB_NAME = 40;
constexpr size_t MAX_LIB = 12;

// Updater local frames (port 333, from a local client only; SPEC-0003 #ota-updater-rules).
constexpr uint8_t U_SCAN = 0x60;     // [rounds u8][round ms u16]
constexpr uint8_t U_LIB = 0x61;      // []: rescan the card, then one U_LIBENT a library entry
constexpr uint8_t U_PUSH = 0x62;     // [image u8][load permille u16][block timeout ms u16][n u8][node u32 x n]
constexpr uint8_t U_PROGRESS = 0x63; // []
constexpr uint8_t U_CANCEL = 0x64;   // []
constexpr uint8_t U_HEARD = 0x65;    // []: one U_NODE a node heard, without a new scan
constexpr uint8_t U_SELF = 0x66;     // [part u8: 0 manifest, 1 block list][offset u32][bytes]: this node's own image
constexpr uint8_t IMAGE_SELF = 0xFF; // U_PUSH image number of the own image
constexpr uint8_t U_NODE = 0x70;     // [i u8][count u8][node u32][rssi i16][snr*4 i16][age s u16][STATUS bytes]
constexpr uint8_t U_LIBENT = 0x71;   // see encodeLibEntry
constexpr uint8_t U_PROG = 0x72;     // see Sender::encodeProgress
constexpr uint8_t U_ACK = 0x73;      // [command u8][result u8]: 0 accepted, else UErr

enum class UErr : uint8_t { OK = 0, BUSY = 1, BAD_FRAME = 2, NO_IMAGE = 3, NO_TARGET = 4, NO_STORAGE = 5, OFF = 6 };

/** The image on storage, as scripts/kota.py writes it: manifest.bin, raw.blocks, raw.bin. */
class ImageSource
{
  public:
    virtual ~ImageSource() {}
    virtual size_t manifest(uint8_t *out, size_t max) = 0;
    virtual uint32_t listSize() = 0;
    virtual bool readList(uint32_t off, uint8_t *out, size_t n) = 0;
    virtual uint32_t rawSize() = 0;
    virtual bool readRaw(uint32_t off, uint8_t *out, size_t n) = 0;
};

/** The updater's own radio: broadcast with hop limit 0 on the primary channel. */
class RadioOut
{
  public:
    virtual ~RadioOut() {}
    virtual bool ready() = 0; // the transmit queue has room
    virtual bool send(const uint8_t *frame, size_t len) = 0;
    virtual uint32_t airtimeMs(size_t len) = 0;
};

/** One node's last STATUS (scripts/kota.py parse_reply), and how it was heard. */
struct Heard {
    uint32_t node = 0;
    uint32_t atMs = 0;
    int16_t rssi = 0;
    int16_t snr4 = 0;
    uint8_t raw[STATUS_MAX] = {};
    uint8_t rawLen = 0;
    uint8_t state = 0, err = 0, runningSlot = 0xFF, bootSlot = 0xFF, imageState = 0xFF, health = 0, testKey = 0;
    uint16_t next = 0, blocks = 0, board = 0;
    uint32_t release = 0;
    char version[MAX_STR + 1] = {};
    char env[MAX_STR + 1] = {}; // empty from a build before U1
};

/** A STATUS frame (0x50) into h; false when it is not one. */
bool parseStatus(const uint8_t *b, size_t n, Heard &h);

enum class Phase : uint8_t {
    IDLE = 0,
    SCAN = 1,
    CHECK = 2, // the raw image on the card against the manifest
    QUERY = 3,
    MANIFEST = 4,
    LIST = 5,
    DATA = 6,
    FINISH = 7,
    DONE = 8,
    FAILED = 9,
    CANCELLED = 10,
};

enum class Why : uint8_t {
    NONE = 0,
    NO_ANSWER = 1,     // a target did not answer QUERY
    TARGET_FAILED = 2, // a target went FAILED (its error is in its status)
    RETRIES = 3,       // a phase ran out of attempts
    BLOCK_RETRIES = 4,
    SOURCE = 5,     // the card did not read
    IMAGE_HASH = 6, // the raw image on the card is not the one the manifest signs
    CANCELLED = 7,
};

struct SenderConfig {
    uint16_t loadPermille = 600; // SPEC-0003 O4
    uint32_t blockTimeoutMs = 4000;
    uint8_t retries = 12;
    uint8_t queryAttempts = 5;
    uint32_t queryTimeoutMs = 30000;
};

struct Target {
    uint32_t node = 0;
    bool fresh = false; // a STATUS since the phase began
    bool acked = false; // the current block
    uint8_t state = 0, err = 0;
    uint16_t next = 0;
};

class Sender
{
  public:
    explicit Sender(RadioOut &out) : out(out) {}

    /** Broadcast QUERY `rounds` times, then listen for roundMs; every STATUS heard goes in the table. */
    bool scan(uint8_t rounds, uint32_t roundMs, uint32_t nowMs);
    /** Install the image on these nodes: check it, QUERY until all answer, then the K2a flow. */
    bool push(ImageSource *src, const uint32_t *nodes, size_t n, const SenderConfig &c, uint32_t nowMs);
    void cancel();
    /** A port 333 frame broadcast by another node. */
    void onReply(uint32_t src, const uint8_t *b, size_t n, int16_t rssi, int16_t snr4, uint32_t nowMs);
    /** Do what is due; returns the milliseconds until it wants to run again. */
    uint32_t step(uint32_t nowMs);

    bool busy() const { return ph != Phase::IDLE && ph != Phase::DONE && ph != Phase::FAILED && ph != Phase::CANCELLED; }
    Phase phase() const { return ph; }
    Why why() const { return reason; }
    uint32_t block() const { return cur; }
    uint32_t blocks() const { return nBlocks; }
    uint32_t resent() const { return resends; }
    size_t targetCount() const { return nTargets; }
    const Target &target(size_t i) const { return targets[i]; }
    size_t heardCount() const { return nHeard; }
    const Heard &heard(size_t i) const { return table[i]; }
    /** U_PROG: [phase][why][n][block u16][of u16][resent u16][elapsed s u32][node u32, state, err, next u16] x n */
    size_t encodeProgress(uint32_t nowMs, uint8_t *o, size_t max) const;

  private:
    enum class Batch : uint8_t { NONE, QUERY, MANIFEST, LIST, BLOCK, FINISH };
    void startBatch(Batch b, uint32_t nowMs);
    bool sendOne(uint32_t nowMs);
    size_t frameAt(uint8_t *f, size_t max);
    bool met() const;
    bool anyFailed() const;
    void enter(Phase p, uint32_t nowMs);
    void fail(Why w);
    uint32_t timeout() const;
    uint8_t attemptsFor() const;
    void nextPhase(uint32_t nowMs);
    Target *find(uint32_t node);
    Heard *heardSlot(uint32_t node);

    RadioOut &out;
    ImageSource *src = nullptr;
    SenderConfig cfg;
    Phase ph = Phase::IDLE;
    Why reason = Why::NONE;
    Target targets[MAX_TARGETS];
    size_t nTargets = 0;
    Heard table[MAX_HEARD];
    size_t nHeard = 0;

    uint8_t man[MAX_MANIFEST] = {};
    size_t manLen = 0;
    Manifest m;
    uint32_t nBlocks = 0, cur = 0, resends = 0;
    uint8_t blockBuf[BLOCK] = {};
    uint32_t blockLen = 0;
    ObjectHash check;
    uint32_t checkOff = 0;

    Batch batch = Batch::NONE;
    uint32_t bOff = 0, bEnd = 0; // the batch's cursor and end, in bytes of what it sends
    bool sending = false;
    uint32_t nextAtMs = 0, waitUntilMs = 0, startMs = 0;
    uint8_t attempt = 0;
    uint8_t scanLeft = 0;
    uint32_t scanRoundMs = 0;
};

/** The card, as the library sees it. Paths are absolute, "/koldnet/lib/<name>/<file>". */
class Storage
{
  public:
    virtual ~Storage() {}
    /** The names of the directories in path, at most max; returns how many. */
    virtual size_t listDirs(const char *path, char (*names)[LIB_NAME], size_t max) = 0;
    /** The file's size, or -1. */
    virtual int32_t size(const char *path) = 0;
    virtual bool read(const char *path, uint32_t off, uint8_t *buf, size_t n) = 0;
};

constexpr uint8_t LIB_NO_MANIFEST = 0x60;
constexpr uint8_t LIB_RAW_SIZE = 0x61;
constexpr uint8_t LIB_LIST_SIZE = 0x62;
constexpr uint8_t LIB_READ = 0x63;

struct LibEntry {
    char name[LIB_NAME] = {};
    uint8_t err = 0; // 0: verified; else a kota::Err or a LIB_ code
    Manifest m;
};

class Library
{
  public:
    static constexpr const char *ROOT = "/koldnet/lib";
    /** Read every directory under ROOT; an entry is verified when its manifest verifies with one of the
     *  keys, raw.bin has the signed size, and raw.blocks has the right size and the signed hash. */
    size_t scan(Storage &s, const uint8_t *const *keys, size_t keyCount);
    size_t count() const { return n; }
    const LibEntry &entry(size_t i) const { return e[i]; }
    /** Verified, same board, same env when the node reports one, and a higher release. */
    bool fits(size_t i, const Heard &h) const;

  private:
    LibEntry e[MAX_LIB];
    size_t n = 0;
};

/** One library entry as files on the storage. */
class LibSource : public ImageSource
{
  public:
    LibSource(Storage &s, const LibEntry &e);
    size_t manifest(uint8_t *out, size_t max) override;
    uint32_t listSize() override;
    bool readList(uint32_t off, uint8_t *out, size_t n) override;
    uint32_t rawSize() override { return m.rawSize; }
    bool readRaw(uint32_t off, uint8_t *out, size_t n) override;

  private:
    Storage &s;
    Manifest m;
    char man[LIB_NAME + 32], list[LIB_NAME + 32], raw[LIB_NAME + 32];
};

/** This node's running image (SPEC-0003 #ota-updater-rules): the manifest and the raw block list come from the
 *  client, in order; the raw bytes from the running app slot. The manifest must verify with one of the keys and
 *  the list must match its signed hash; the Sender's CHECK then hashes the raw bytes against the manifest. */
class SelfSource : public ImageSource
{
  public:
    typedef bool (*RawRead)(uint32_t off, uint8_t *out, size_t n);
    explicit SelfSource(RawRead r) : rd(r) {}
    ~SelfSource() { delete[] list; }
    /** One U_SELF chunk; returns 0 when taken, else a kota::Err or LErr value. */
    uint8_t put(uint8_t part, uint32_t off, const uint8_t *b, size_t n, const uint8_t *const *keys, size_t keyCount);
    bool complete() const { return manOk && list && listGot == listLen; }
    size_t manifest(uint8_t *out, size_t max) override;
    uint32_t listSize() override { return complete() ? listLen : 0; }
    bool readList(uint32_t off, uint8_t *out, size_t n) override;
    uint32_t rawSize() override { return manOk ? m.rawSize : 0; }
    bool readRaw(uint32_t off, uint8_t *out, size_t n) override { return rd && rd(off, out, n); }
    const Manifest &mf() const { return m; }

  private:
    RawRead rd;
    uint8_t man[MAX_MANIFEST] = {};
    size_t manLen = 0;
    bool manOk = false;
    Manifest m;
    uint8_t *list = nullptr;
    uint32_t listLen = 0, listGot = 0;
};

/** U_LIBENT: [i][count][err][board u16][release u32][raw size u32][flags][env len][env][ver len][ver][name len][name] */
size_t encodeLibEntry(const Library &lib, size_t i, uint8_t *o, size_t max);
/** U_NODE for table entry i. */
size_t encodeNode(const Sender &s, size_t i, uint32_t nowMs, uint8_t *o, size_t max);

} // namespace kota
