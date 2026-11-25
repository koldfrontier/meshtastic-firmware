// koldnet SD loader: installs a staged, signed image from the microSD card into app0 (SPEC-0003
// #ota-design item 6, TASK-20261125-02). The decisions are in src/mesh/koldnet/KotaLoader.cpp and are
// host-tested; this file is the card, the flash, NVS and the boot slot. It writes only app0 and otadata
// (and its own NVS record), never the partition table or the bootloader.
#include "mesh/koldnet/KotaLoader.h"
#include <Arduino.h>
#include <Ed25519.h>
#include <Preferences.h>
#include <SD.h>
#include <SPI.h>
#include <esp_flash_partitions.h>
#include <esp_image_format.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <mbedtls/sha256.h>

#ifndef KOLDNET_KOTA_TEST_KEY
#define KOLDNET_KOTA_TEST_KEY 0
#endif

// Printed at boot, and what the app looks for in ota_1 before it stages an image.
static const char MAGIC[] __attribute__((used)) = "KOLDNET-KOTA-SD-LOADER-1";
static_assert(sizeof MAGIC == sizeof kota::LOADER_MAGIC, "the app looks for kota::LOADER_MAGIC");

static const uint8_t RELEASE_KEY[32] = {0xbf, 0x32, 0x2a, 0x58, 0xc1, 0xdc, 0x7e, 0x3c, 0xd4, 0x2f, 0xa5,
                                        0xaa, 0x09, 0x17, 0x0a, 0xea, 0xc9, 0xb5, 0x6c, 0x44, 0xb8, 0x07,
                                        0x25, 0x1f, 0xf1, 0xac, 0x4d, 0x77, 0xe6, 0x63, 0xb1, 0xb1};
#if KOLDNET_KOTA_TEST_KEY
static const char TEST_SEED_TEXT[] = "koldnet KOTA throwaway test key v1";
#endif
static uint8_t testKey[32];

static const char *IMAGE_PATH = "/koldnet/ota.bin";
static const char *MANIFEST_PATH = "/koldnet/ota.man";
static const char *PREVIOUS_PATH = "/koldnet/prev.bin";
static uint8_t buf[kota::BLOCK];

class Sha
{
  public:
    Sha()
    {
        mbedtls_sha256_init(&c);
        mbedtls_sha256_starts_ret(&c, 0);
    }
    ~Sha() { mbedtls_sha256_free(&c); }
    void update(const uint8_t *d, size_t n) { mbedtls_sha256_update_ret(&c, d, n); }
    void finish(uint8_t out[kota::HASH]) { mbedtls_sha256_finish_ret(&c, out); }

  private:
    mbedtls_sha256_context c;
};

class Esp : public kota::LoaderPlatform
{
  public:
    const esp_partition_t *app = nullptr;
    bool card = false;

    bool load(kota::LoaderRec &r) override
    {
        Preferences p;
        if (!p.begin(kota::LOADER_NVS, true))
            return false;
        bool ok = p.getBytes(kota::LOADER_NVS_KEY, &r, sizeof r) == sizeof r;
        p.end();
        return ok;
    }
    bool store(const kota::LoaderRec &r) override
    {
        Preferences p;
        if (!p.begin(kota::LOADER_NVS, false))
            return false;
        bool ok = p.putBytes(kota::LOADER_NVS_KEY, &r, sizeof r) == sizeof r;
        p.end();
        return ok;
    }
    kota::AppState appState() override
    {
        esp_ota_img_states_t st;
        if (esp_ota_get_state_partition(app, &st) != ESP_OK)
            return kota::AppState::OTHER;
        return st == ESP_OTA_IMG_ABORTED || st == ESP_OTA_IMG_INVALID ? kota::AppState::BAD : kota::AppState::OTHER;
    }
    bool appVerify(uint32_t &len) override
    {
        esp_partition_pos_t pos = {app->address, app->size};
        esp_image_metadata_t md = {};
        if (esp_image_verify(ESP_IMAGE_VERIFY_SILENT, &pos, &md) != ESP_OK)
            return false;
        len = md.image_len;
        return true;
    }
    bool appHash(uint32_t len, uint8_t sha[kota::HASH]) override
    {
        Sha h;
        for (uint32_t o = 0; o < len;) {
            size_t n = len - o < sizeof buf ? len - o : sizeof buf;
            if (esp_partition_read(app, o, buf, n) != ESP_OK)
                return false;
            h.update(buf, n);
            o += n;
        }
        h.finish(sha);
        return true;
    }
    uint32_t appSlotSize() override { return app->size; }
    bool readManifest(uint8_t *out, size_t max, size_t &len) override
    {
        File f = card ? SD.open(MANIFEST_PATH, FILE_READ) : File();
        if (!f || f.size() > max)
            return false;
        len = f.size();
        bool ok = f.read(out, len) == len;
        f.close();
        return ok;
    }
    bool fileHash(kota::LoaderFile which, uint32_t len, uint8_t sha[kota::HASH]) override
    {
        File f = card ? SD.open(path(which), FILE_READ) : File();
        if (!f || f.size() != len)
            return false;
        Sha h;
        for (uint32_t o = 0; o < len;) {
            size_t n = len - o < sizeof buf ? len - o : sizeof buf;
            if (f.read(buf, n) != n)
                return false;
            h.update(buf, n);
            o += n;
        }
        f.close();
        h.finish(sha);
        return true;
    }
    bool copyAppToPrevious(uint32_t len, uint8_t sha[kota::HASH]) override
    {
        if (!card)
            return false;
        SD.remove(PREVIOUS_PATH);
        File f = SD.open(PREVIOUS_PATH, FILE_WRITE);
        if (!f)
            return false;
        Sha h;
        for (uint32_t o = 0; o < len;) {
            size_t n = len - o < sizeof buf ? len - o : sizeof buf;
            if (esp_partition_read(app, o, buf, n) != ESP_OK || f.write(buf, n) != n) {
                f.close();
                return false;
            }
            h.update(buf, n);
            o += n;
        }
        f.close();
        h.finish(sha);
        return true;
    }
    bool copyToApp(kota::LoaderFile which, uint32_t len) override
    {
        File f = card ? SD.open(path(which), FILE_READ) : File();
        if (!f || f.size() != len || len > app->size)
            return false;
        uint32_t t0 = millis();
        for (uint32_t o = 0; o < len;) {
            if (o % 65536 == 0) {
                uint32_t e = len - o < 65536 ? (len - o + 4095) & ~4095u : 65536;
                if (esp_partition_erase_range(app, o, e) != ESP_OK)
                    return false;
            }
            size_t n = len - o < sizeof buf ? len - o : sizeof buf;
            if (f.read(buf, n) != n || esp_partition_write(app, o, buf, n) != ESP_OK)
                return false;
            o += n;
        }
        f.close();
        Serial.printf("loader: app0 written in %u ms\n", (unsigned)(millis() - t0));
        return true;
    }
    bool bootApp(bool trusted) override
    {
        esp_err_t e = esp_ota_set_boot_partition(app); // checks the image; its state is NEW
        if (e != ESP_OK) {
            Serial.printf("loader: set boot %s\n", esp_err_to_name(e));
            return false;
        }
        return trusted ? markValid() : true;
    }
    void log(const char *text, unsigned value) override { Serial.printf("loader: %s %u\n", text, value); }

    void mount()
    {
        static SPIClass bus(HSPI);
        for (int i = 0; i < 3 && !card; i++) {
            bus.begin(14, 2, 15, 13); // hardware/lilygo-lora32-v2.1.md #microsd-slot
            card = SD.begin(13, bus, 10000000);
            if (!card) {
                SD.end();
                delay(500);
            }
        }
        Serial.printf("loader: card %s, %u MB\n", card ? "mounted" : "NOT mounted", card ? (unsigned)(SD.cardSize() >> 20) : 0);
    }
    void unmount()
    {
        SD.end();
        card = false;
    }

  private:
    static const char *path(kota::LoaderFile w) { return w == kota::LoaderFile::IMAGE ? IMAGE_PATH : PREVIOUS_PATH; }

    /** The image in app0 ran before, so it needs no new health check: VALID instead of NEW in otadata. A power
     *  loss between the erase and the write leaves the other entry, which boots this loader again. */
    bool markValid()
    {
        const esp_partition_t *d = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, NULL);
        esp_ota_select_entry_t e[2];
        if (!d || esp_partition_read(d, 0, &e[0], sizeof e[0]) != ESP_OK ||
            esp_partition_read(d, 0x1000, &e[1], sizeof e[1]) != ESP_OK)
            return false;
        int i = e[1].ota_seq != 0xFFFFFFFF && (e[0].ota_seq == 0xFFFFFFFF || e[1].ota_seq > e[0].ota_seq);
        if (e[i].ota_seq == 0xFFFFFFFF || (e[i].ota_seq - 1) % 2 != 0) // must be app0's entry, the one just written
            return false;
        e[i].ota_state = ESP_OTA_IMG_VALID; // the CRC covers the sequence number only
        return esp_partition_erase_range(d, i * 0x1000, 0x1000) == ESP_OK &&
               esp_partition_write(d, i * 0x1000, &e[i], sizeof e[i]) == ESP_OK;
    }
};

static Esp esp;

void setup()
{
    Serial.begin(115200);
    delay(50);
    const esp_app_desc_t *d = esp_ota_get_app_description();
    Serial.printf("\n%s %s board %d test key %d elf %02x%02x%02x%02x%02x%02x%02x%02x\n", MAGIC, KOLDNET_LOADER_ENV,
                  KOLDNET_LOADER_BOARD_ID, KOLDNET_KOTA_TEST_KEY, d->app_elf_sha256[0], d->app_elf_sha256[1],
                  d->app_elf_sha256[2], d->app_elf_sha256[3], d->app_elf_sha256[4], d->app_elf_sha256[5],
                  d->app_elf_sha256[6], d->app_elf_sha256[7]);
    esp.app = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
}

void loop()
{
    if (!esp.app) {
        Serial.println("loader: no ota_0");
        delay(5000);
        return;
    }
#if KOLDNET_KOTA_TEST_KEY
    uint8_t priv[32];
    mbedtls_sha256_ret((const uint8_t *)TEST_SEED_TEXT, strlen(TEST_SEED_TEXT), priv, 0);
    Ed25519::derivePublicKey(testKey, priv);
#endif
    static const uint8_t *const keys[2] = {RELEASE_KEY, testKey};
    esp.mount();
    kota::KotaLoader l(esp, KOLDNET_LOADER_BOARD_ID, KOLDNET_LOADER_ENV, keys, KOLDNET_KOTA_TEST_KEY ? 2 : 1);
    kota::LoaderAction a = l.run();
    esp.unmount();
    Serial.printf("loader: done, action %u, at %u ms\n", (unsigned)a, (unsigned)millis());
    Serial.flush();
    if (a == kota::LoaderAction::WAIT)
        delay(5000);
    else
        ESP.restart();
}
