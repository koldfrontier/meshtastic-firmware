#include "KotaSdFlash.h"

#if defined(ARCH_ESP32) && KOLDNET_KOTA_SD

#include <Preferences.h>
#include <SPI.h>
#include <esp_ota_ops.h>
#include <string.h>

// LoRa32 V2.1: the card is on its own bus, HSPI (hardware/lilygo-lora32-v2.1.md #microsd-slot).
#ifndef KOLDNET_SD_SCK
#define KOLDNET_SD_SCK 14
#define KOLDNET_SD_MISO 2
#define KOLDNET_SD_MOSI 15
#define KOLDNET_SD_CS 13
#endif
#ifndef KOLDNET_SD_HZ
#define KOLDNET_SD_HZ 10000000
#endif
#ifndef KOLDNET_KOTA_TEST_TAMPER_RELEASE
#define KOLDNET_KOTA_TEST_TAMPER_RELEASE 0 // test builds only: spoil the staged image of this release after the check
#endif

static const char *DIR = "/koldnet";
static const char *IMAGE = "/koldnet/ota.bin";
static const char *MANIFEST = "/koldnet/ota.man";
static const char *HEAP_KEY = "failheap"; // free and largest heap block when staging last failed to finish

static SPIClass *bus;

const esp_partition_t *KotaSdFlash::app0()
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
}

const esp_partition_t *KotaSdFlash::loader()
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_1, NULL);
}

bool KotaSdFlash::loaderPresent(const esp_partition_t *p)
{
    // The Arduino app descriptor is the same for every sketch, so look for the loader's own string.
    static const size_t STEP = 1024;
    const size_t ml = sizeof(kota::LOADER_MAGIC) - 1;
    uint8_t *buf = (uint8_t *)malloc(STEP + ml);
    if (!buf)
        return false;
    bool found = false;
    for (uint32_t off = 0; off < p->size && !found; off += STEP) {
        size_t n = STEP + ml;
        if (off + n > p->size)
            n = p->size - off;
        if (esp_partition_read(p, off, buf, n) != ESP_OK)
            break;
        for (size_t i = 0; i + ml <= n && !found; i++)
            found = buf[i] == 'K' && memcmp(buf + i, kota::LOADER_MAGIC, ml) == 0;
    }
    free(buf);
    return found;
}

bool KotaSdFlash::mount()
{
    if (mounted)
        return true;
    if (!bus)
        bus = new SPIClass(HSPI);
    bus->begin(KOLDNET_SD_SCK, KOLDNET_SD_MISO, KOLDNET_SD_MOSI, KOLDNET_SD_CS);
    uint32_t before = ESP.getFreeHeap(), largest = ESP.getMaxAllocHeap();
    // Each open file costs a 4 KB sector buffer, in one block for all of them: ask for the two we use.
    if (!SD.begin(KOLDNET_SD_CS, *bus, KOLDNET_SD_HZ, "/sd", 2)) {
        LOG_ERROR("KOTA: SD card does not mount; free heap %u, largest %u", (unsigned)before, (unsigned)largest);
        bus->end();
        return false;
    }
    mounted = true;
    LOG_INFO("KOTA: SD card type %u, %u MB, FAT %u MB used of %u MB; free heap %u before, %u mounted, largest %u",
             (unsigned)SD.cardType(), (unsigned)(SD.cardSize() >> 20), (unsigned)(SD.usedBytes() >> 20),
             (unsigned)(SD.totalBytes() >> 20), (unsigned)before, (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    return true;
}

void KotaSdFlash::unmount()
{
    if (!mounted)
        return;
    SD.end();
    bus->end();
    mounted = false;
}

uint32_t KotaSdFlash::spareSize()
{
    const esp_partition_t *a = app0(), *l = loader();
    if (!a || esp_ota_get_running_partition() != a || !l)
        return 0;
    if (!loaderPresent(l)) {
        LOG_ERROR("KOTA: no koldnet loader in ota_1, an image cannot be installed");
        return 0; // the manifest is refused with SLOT
    }
    return a->size;
}

bool KotaSdFlash::beginFailed(uint8_t step)
{
    LOG_ERROR("KOTA: staging could not start, step %u", (unsigned)step);
    unmount();
    kota::LoaderRec r; // a serial API client hides the log, so the step is kept for the next boot's log
    if (!loadRec(r))
        r = kota::LoaderRec();
    r.detail = 0xB0 + step;
    storeRec(r);
    return false;
}

bool KotaSdFlash::begin(uint32_t size)
{
    if (!mount())
        return beginFailed(1);
    if (!SD.exists(DIR) && !SD.mkdir(DIR))
        return beginFailed(2);
    SD.remove(MANIFEST);
    SD.remove(IMAGE);
    if (SD.totalBytes() - SD.usedBytes() < 2ull * size + 65536) { // the image, and the loader's copy of the running one
        LOG_ERROR("KOTA: SD card full");
        return beginFailed(3);
    }
    f = SD.open(IMAGE, FILE_WRITE);
    if (!f)
        return beginFailed(4);
    want = size;
    got = 0;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts_ret(&sha, 0);
    LOG_INFO("KOTA: staging %u bytes on the SD card, free heap %u", (unsigned)size, (unsigned)ESP.getFreeHeap());
    return true;
}

bool KotaSdFlash::write(const uint8_t *d, size_t n)
{
    if (!f || f.write(d, n) != n)
        return false;
    mbedtls_sha256_update_ret(&sha, d, n);
    got += n;
    return true;
}

bool KotaSdFlash::finishFailed(uint8_t step)
{
    // A serial API client hides the log, so the step and the heap are kept for the next boot's log.
    uint32_t heap[2] = {ESP.getFreeHeap(), ESP.getMaxAllocHeap()};
    LOG_ERROR("KOTA: staging could not finish, step 0x%02x; free heap %u, largest %u", (unsigned)step, (unsigned)heap[0],
              (unsigned)heap[1]);
    unmount();
    kota::LoaderRec r;
    if (!loadRec(r))
        r = kota::LoaderRec();
    r.detail = step;
    storeRec(r);
    Preferences p; // its own key: the loader's record keeps its layout
    if (p.begin(kota::LOADER_NVS, false)) {
        p.putBytes(HEAP_KEY, heap, sizeof heap);
        p.end();
    }
    return false;
}

bool KotaSdFlash::end()
{
    mbedtls_sha256_finish_ret(&sha, written);
    mbedtls_sha256_free(&sha);
    f.close();
    if (got != want)
        return finishFailed(0xC1);
    File in = SD.open(IMAGE, FILE_READ);
    if (!in)
        return finishFailed(0xC2);
    if (in.size() != want) {
        in.close();
        return finishFailed(0xC3);
    }
    // Static, not from the heap: this runs at the end of an install, when the heap is at its lowest.
    static uint8_t buf[1024];
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts_ret(&c, 0);
    uint8_t step = 0;
    for (uint32_t left = want; left && !step;) {
        size_t n = left < sizeof buf ? left : sizeof buf;
        if (in.read(buf, n) != n)
            step = 0xC4;
        // ESP image header: magic 0xE9, chip id 0 (ESP32) at offset 12
        else if (left == want && !(buf[0] == 0xE9 && buf[12] == 0 && buf[13] == 0))
            step = 0xC5;
        else
            mbedtls_sha256_update_ret(&c, buf, n);
        left -= n;
    }
    uint8_t back[kota::HASH];
    mbedtls_sha256_finish_ret(&c, back);
    mbedtls_sha256_free(&c);
    in.close();
    if (!step && memcmp(back, written, sizeof back) != 0)
        step = 0xC6;
    LOG_INFO("KOTA: staged image %s, %u bytes", step ? "does NOT read back" : "reads back", (unsigned)got);
    return step ? finishFailed(step) : true;
}

bool KotaSdFlash::setBoot()
{
    size_t len = 0;
    const uint8_t *man = installer ? installer->manifestBytes(len) : nullptr;
    const esp_partition_t *l = loader();
    if (!man || !len || !l)
        return finishFailed(0xD1);
    File m = SD.open(MANIFEST, FILE_WRITE);
    if (!m)
        return finishFailed(0xD2);
    bool ok = m.write(man, len) == len;
    m.close();
    if (!ok)
        return finishFailed(0xD3);
#if KOLDNET_KOTA_TEST_TAMPER_RELEASE
    if (ok && installer->manifest().release == KOLDNET_KOTA_TEST_TAMPER_RELEASE) {
        File t = SD.open(IMAGE, "r+");
        uint32_t at = want / 2;
        int c = t && t.seek(at) ? t.read() : -1;
        bool done = c >= 0 && t.seek(at) && t.write((uint8_t)(c ^ 1)) == 1;
        if (t)
            t.close();
        LOG_WARN("KOTA TEST: one byte of the staged image changed at %u: %s", (unsigned)at, done ? "done" : "FAILED");
    }
#endif
    unmount();
    kota::LoaderRec r;
    if (!loadRec(r))
        r = kota::LoaderRec();
    r.phase = kota::LoaderPhase::IDLE; // this app runs, so app0 is good
    r.haveWant = 1;
    mbedtls_sha256_ret(man, len, r.want, 0);
    r.result = kota::LoaderResult::NONE;
    r.detail = 0;
    if (!storeRec(r))
        return finishFailed(0xD4);
    if (esp_ota_set_boot_partition(l) != ESP_OK)
        return finishFailed(0xD5);
    return true;
}

void KotaSdFlash::abort()
{
    if (f) {
        f.close();
        mbedtls_sha256_free(&sha);
    }
    unmount();
}

bool KotaSdFlash::loadRec(kota::LoaderRec &r)
{
    Preferences p;
    if (!p.begin(kota::LOADER_NVS, true))
        return false;
    bool ok = p.getBytes(kota::LOADER_NVS_KEY, &r, sizeof r) == sizeof r && r.version == kota::LOADER_REC_VERSION;
    p.end();
    return ok;
}

bool KotaSdFlash::storeRec(const kota::LoaderRec &r)
{
    Preferences p;
    if (!p.begin(kota::LOADER_NVS, false))
        return false;
    bool ok = p.putBytes(kota::LOADER_NVS_KEY, &r, sizeof r) == sizeof r;
    p.end();
    return ok;
}

void KotaSdFlash::logLoaderResult()
{
    kota::LoaderRec r;
    if (loadRec(r))
        LOG_INFO("KOTA: loader phase %u result %u detail 0x%02x, previous image %u bytes", (unsigned)r.phase,
                 (unsigned)r.result, (unsigned)r.detail, (unsigned)r.prevLen);
    Preferences p;
    uint32_t heap[2] = {};
    if (p.begin(kota::LOADER_NVS, true)) {
        if (p.getBytes(HEAP_KEY, heap, sizeof heap) == sizeof heap)
            LOG_INFO("KOTA: the last failed staging had free heap %u, largest %u", (unsigned)heap[0], (unsigned)heap[1]);
        p.end();
    }
    // No mount at boot: once the card has been initialised it holds GPIO2 (its DAT0) high until it loses power,
    // and the ROM then refuses USB download mode (TASK-20261125-02, 11:02). The card is mounted only to stage.
}

#endif
