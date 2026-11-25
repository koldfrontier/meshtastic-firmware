#pragma once
// koldnet SD loader for 4 MB boards (SPEC-0003 #ota-design item 6, TASK-20261125-02): what the loader
// in ota_1 does on each boot. Pure logic: the card, the flash, the boot slot and NVS are behind Platform,
// so a host test cuts the power at every step (test/test_kota_loader). The ESP32 side of the loader is
// koldnet-loader/; the app side, which stages the image and asks for the install, is KotaSdFlash.

#include "KotaImage.h"

namespace kota
{

constexpr char LOADER_MAGIC[] = "KOLDNET-KOTA-SD-LOADER-1"; // in the loader's image; the app looks for it

// The record is in NVS, which a card swap cannot reach. The app writes it when it asks for an install.
constexpr char LOADER_NVS[] = "kotaldr";
constexpr char LOADER_NVS_KEY[] = "rec";
constexpr uint8_t LOADER_REC_VERSION = 1;

enum class LoaderPhase : uint8_t { IDLE = 0, WRITING = 1, TRIAL = 2, RESTORING = 3 };

enum class LoaderResult : uint8_t {
    NONE = 0,
    INSTALLED = 1, // app0 written and set to boot; its own health check comes next
    REFUSED = 2,   // the card's data is not what the app verified; app0 untouched. detail: kota::Err or 0x80 + step
    RESTORED = 3,  // the new image did not prove itself; the previous one is back
    NO_PREVIOUS_COPY = 4, // the running image could not be kept on the card; app0 untouched
    APP_BAD = 5,          // nothing left to try
};

struct __attribute__((packed)) LoaderRec {
    uint8_t version = LOADER_REC_VERSION;
    LoaderPhase phase = LoaderPhase::IDLE;
    uint8_t haveWant = 0;
    uint8_t want[HASH] = {}; // SHA-256 of the manifest the app accepted
    uint32_t prevLen = 0;    // the previous image on the card; 0: none
    uint8_t prevSha[HASH] = {};
    LoaderResult result = LoaderResult::NONE;
    uint8_t detail = 0;
};

enum class LoaderFile : uint8_t { IMAGE, PREVIOUS };
enum class AppState : uint8_t { OTHER, BAD }; // BAD: the bootloader marked app0 ABORTED or INVALID

class LoaderPlatform
{
  public:
    virtual ~LoaderPlatform() {}
    virtual bool load(LoaderRec &r) = 0; // false: no record
    virtual bool store(const LoaderRec &r) = 0;
    virtual AppState appState() = 0;
    virtual bool appVerify(uint32_t &len) = 0; // the ESP32 image check on app0; len with its appended hash
    virtual bool appHash(uint32_t len, uint8_t sha[HASH]) = 0;
    virtual uint32_t appSlotSize() = 0;
    virtual bool readManifest(uint8_t *buf, size_t max, size_t &len) = 0;
    virtual bool fileHash(LoaderFile f, uint32_t len, uint8_t sha[HASH]) = 0; // false also when the size differs
    virtual bool copyAppToPrevious(uint32_t len, uint8_t sha[HASH]) = 0;      // sha of what was read from app0
    virtual bool copyToApp(LoaderFile f, uint32_t len) = 0;                   // erase and write app0
    virtual bool bootApp(bool trusted) = 0; // trusted: it ran before, mark it VALID; else it must pass its health check
    virtual void log(const char *text, unsigned value) = 0;
};

enum class LoaderAction : uint8_t { BOOT_APP, INSTALL, RESTORE, WAIT };

struct LoaderFacts {
    LoaderPhase phase;
    bool wanted;
    bool cardOk;
    bool appOk;
    bool appBad; // marked bad by the bootloader: it ran and did not prove itself
    bool prevOk;
};

LoaderAction loaderDecide(const LoaderFacts &f);

class KotaLoader
{
  public:
    KotaLoader(LoaderPlatform &p, uint16_t boardId, const char *env, const uint8_t *const *keys, size_t keyCount)
        : p(p), boardId(boardId), env(env), keys(keys), keyCount(keyCount)
    {
    }
    /** One boot. Everything but WAIT ends with app0 set to boot, and the caller restarts. */
    LoaderAction run();

  private:
    uint8_t checkCard(const LoaderRec &r, Manifest &m); // 0 good, else a kota::Err or 0x80 + step
    bool prevGood(const LoaderRec &r);
    LoaderAction install(LoaderRec &r, const Manifest &m, bool appOk, uint32_t appLen);
    LoaderAction restore(LoaderRec &r);
    LoaderAction bootOld(LoaderRec &r, LoaderResult res, uint8_t detail);

    LoaderPlatform &p;
    uint16_t boardId;
    const char *env;
    const uint8_t *const *keys;
    size_t keyCount;
};

} // namespace kota
