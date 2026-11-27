#pragma once
// koldnet KOTA for boards whose second app slot is too small (LoRa32, 4 MB): the image is staged on the
// microSD card, and the koldnet loader in ota_1 writes it into app0 (SPEC-0003 #ota-design item 6,
// TASK-20261125-02). Set KOLDNET_KOTA_SD=1 in the env.

#include "configuration.h"

#if defined(ARCH_ESP32) && KOLDNET_KOTA_SD

#include "mesh/koldnet/KotaLoader.h"
#include "mesh/koldnet/KotaLocal.h"
#include <SD.h>
#include <esp_partition.h>
#include <mbedtls/sha256.h>

class KotaSdFlash : public kota::Flash
{
  public:
    void attach(const kota::Installer *i) { installer = i; }
    /** The last thing the loader did, for the boot log. */
    void logLoaderResult();
    /** A failed end() or setBoot() keeps its step (0xC1 to 0xD5) in the loader record's detail. */
    bool finishFailed(uint8_t step);
    /** Mount the card for the field updater's library (SPEC-0003 #ota-updater); stays mounted. */
    bool mountCard() { return mount(); }

    uint32_t spareSize() override;
    bool begin(uint32_t size) override;
    bool write(const uint8_t *d, size_t n) override;
    bool end() override;
    bool setBoot() override;
    void abort() override;

  private:
    bool mount();
    void unmount();
    bool beginFailed(uint8_t step);
    static const esp_partition_t *app0();
    static const esp_partition_t *loader();
    static bool loaderPresent(const esp_partition_t *p);
    static bool loadRec(kota::LoaderRec &r);
    static bool storeRec(const kota::LoaderRec &r);

    const kota::Installer *installer = nullptr;
    bool mounted = false;
    File f;
    uint32_t want = 0, got = 0;
    mbedtls_sha256_context sha;
    uint8_t written[kota::HASH] = {};
};

#endif
