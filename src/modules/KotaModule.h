#pragma once
// koldnet OTA (SPEC-0003 #ota-local, phase K1): the local install over the API, the health check
// after an install, and the rollback hook. ESP32 only. The session logic is kota::Installer
// (src/mesh/koldnet/KotaLocal.h), tested on the host.

#include "configuration.h"

#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_KOTA

#include "concurrency/OSThread.h"
#include "mesh/MeshModule.h"
#include "mesh/koldnet/KotaLocal.h"

class KotaModule : public MeshModule, private concurrency::OSThread
{
  public:
    KotaModule();

    /** Called by PhoneAPI for every packet from a local client, before the router.
     *  Returns true when it was a KOTA local frame (consumed). */
    bool handleLocal(const meshtastic_MeshPacket &p);

  protected:
    bool wantPacket(const meshtastic_MeshPacket *p) override { return true; }
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    int32_t runOnce() override;

  private:
    void reply(const uint8_t *buf, size_t len);
    void fillStatus(kota::PlatformStatus &ps);
    bool heardOther = false;
    uint8_t health = 0; // 0 not needed, 1 waiting, 2 passed
    uint32_t healthStartMs = 0;
    uint32_t rebootAtMs = 0;
};

extern KotaModule *kotaModule;

#endif
