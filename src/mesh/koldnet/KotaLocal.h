#pragma once
// koldnet local install over the API (SPEC-0003 #ota-local, phase K1): the session state machine.
// Pure logic: the flash is behind the Flash interface, so it is tested on the host (test/test_kota).
// The ESP32 glue and the health check are in src/modules/KotaModule.cpp.

#include "KotaImage.h"

namespace kota
{

constexpr uint16_t PORT = 333;

// Port 333 type codes. 0x01 to 0x3F are reserved for the mesh frames (K2, K3).
constexpr uint8_t L_MANIFEST = 0x40;
constexpr uint8_t L_LIST = 0x41;
constexpr uint8_t L_DATA = 0x42;
constexpr uint8_t L_FINISH = 0x43;
constexpr uint8_t L_ABORT = 0x44;
constexpr uint8_t L_QUERY = 0x45;
constexpr uint8_t L_STATUS = 0x50;
constexpr uint8_t L_BLOCK = 0x51;

constexpr size_t DATA_MAX = 224;
constexpr uint32_t SESSION_TIMEOUT_MS = 60000;
constexpr uint32_t RADIO_TIMEOUT_MS = 600000; // a sender on a slow preset, or one that is restarted
constexpr size_t MAX_KEYS = 2;

// Local error codes, after the kota::Err values.
enum class LErr : uint8_t {
    OK = 0,
    SEQUENCE = 0x40, // a frame out of order or for another state
    FRAME = 0x41,    // too short, or a length out of range
    SLOT = 0x42,     // the image is larger than the spare slot
    FLASH = 0x43,    // the flash refused a begin, write, end or set-boot
    MEMORY = 0x44,   // no memory for the block list
    TIMEOUT = 0x45,
    UNKNOWN_KEY = 0x46,
};

enum class State : uint8_t { IDLE = 0, MANIFEST = 1, LIST = 2, DATA = 3, DONE = 4, FAILED = 5 };

/** The spare app slot. The ESP32 glue implements it with esp_ota_*; the tests with RAM. */
class Flash
{
  public:
    virtual ~Flash() {}
    virtual uint32_t spareSize() = 0;
    virtual bool begin(uint32_t imageSize) = 0;
    virtual bool write(const uint8_t *data, size_t len) = 0;
    virtual bool end() = 0; // the image is complete; the platform may check it
    virtual bool setBoot() = 0;
    virtual void abort() = 0;
};

/** What the running image is. */
struct Identity {
    uint16_t boardId = 0;
    const char *env = "";
    uint32_t release = 0;
    const uint8_t *keys[MAX_KEYS] = {};
    size_t keyCount = 0;
};

/** The platform facts that go into STATUS. */
struct PlatformStatus {
    uint8_t runningSlot = 0xFF;
    uint8_t bootSlot = 0xFF;
    uint8_t imageState = 0xFF;
    uint8_t health = 0;
    uint8_t testKey = 0;
    uint8_t elfSha[8] = {};
    const char *version = "";
};

enum class Reply : uint8_t { NONE, STATUS, BLOCK };

class Installer
{
  public:
    Installer(Flash &flash, const Identity &id) : flash(flash), id(id) {}
    ~Installer();

    /** Handle one frame. The caller sends the reply it names (encodeStatus or encodeBlock). */
    Reply handle(const uint8_t *frame, size_t len, uint32_t nowMs);
    /** As handle(), for a frame broadcast by node src over LoRa (K2a, SPEC-0003 #ota-mesh). One session
     *  at a time, from one source: a frame from another source is ignored while a session is open. A
     *  broadcast reaches nodes it is not for, and frames get lost, so this never answers a frame that is
     *  out of place, skips list frames that are out of order (the sender sends the list again), keeps
     *  the session when the same manifest is sent again (a sender that resumes), and repeats the answer
     *  to a FINISH it has already done. */
    Reply handleRadio(uint32_t src, const uint8_t *frame, size_t len, uint32_t nowMs);
    /** Drops a session that has been silent for SESSION_TIMEOUT_MS. */
    void tick(uint32_t nowMs);

    size_t encodeStatus(const PlatformStatus &ps, uint8_t *out, size_t outMax) const;
    size_t encodeBlock(uint8_t *out, size_t outMax) const;

    State state() const { return st; }
    uint8_t error() const { return err; }
    uint32_t nextBlock() const { return next; }
    uint32_t blocks() const { return st >= State::LIST ? blockCount(m.rawSize) : 0; }
    /** FINISH asked for a reboot, and the boot slot is set. */
    bool rebootRequested() const { return reboot; }
    const Manifest &manifest() const { return m; }
    /** The block list is held from LIST until the image hash checks at FINISH. */
    bool holdsBlockList() const { return list != nullptr; }
    /** The manifest as received, for a Flash that stores it (KotaSdFlash). Valid in setBoot(). */
    const uint8_t *manifestBytes(size_t &len) const
    {
        len = manTotal;
        return man;
    }

  private:
    Reply onManifest(const uint8_t *b, size_t n);
    Reply onList(const uint8_t *b, size_t n);
    Reply onData(const uint8_t *b, size_t n);
    Reply onFinish(const uint8_t *b, size_t n);
    Reply fail(uint8_t code);
    bool active() const { return st == State::MANIFEST || st == State::LIST || st == State::DATA; }
    void drop();

    Flash &flash;
    Identity id;
    State st = State::IDLE;
    uint8_t err = 0;
    bool reboot = false;
    bool flashOpen = false;
    uint32_t lastMs = 0;
    uint32_t source = 0; // who opened the session: 0 the local API, else a node number

    uint8_t man[MAX_MANIFEST] = {};
    size_t manTotal = 0, manGot = 0;
    Manifest m;

    uint8_t *list = nullptr;
    size_t listLen = 0, listGot = 0;

    uint8_t block[BLOCK] = {};
    uint32_t next = 0;
    uint32_t fill = 0;
    uint16_t replyBlock = 0;
    uint8_t replyResult = 0;
    ObjectHash raw;
};

} // namespace kota
