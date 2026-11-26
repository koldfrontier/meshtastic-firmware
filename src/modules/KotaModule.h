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
    /** A frame broadcast with hop limit 0 on the primary channel (the field updater's sender). */
    void sendRadio(const uint8_t *buf, size_t len) { replyRadio(buf, len, 0); }

  protected:
    bool wantPacket(const meshtastic_MeshPacket *p) override { return true; }
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    int32_t runOnce() override;

  private:
    void reply(const uint8_t *buf, size_t len);
    size_t answer(kota::Reply r, uint8_t *buf, size_t max);
    void replyRadio(const uint8_t *buf, size_t len, uint8_t channel);
    void fillStatus(kota::PlatformStatus &ps);
    void handleUpdater(const uint8_t *b, size_t n);
    void ack(uint8_t cmd, uint8_t result, uint8_t extra = 0);
    uint32_t updaterStep(uint32_t now);
    // A STATUS answering a broadcast QUERY waits a random time: every node answers at once (TASK-20261125-13 item 1).
    uint8_t pendingBuf[100] = {};
    size_t pendingLen = 0;
    uint8_t pendingChannel = 0;
    uint32_t pendingAtMs = 0;
    // The updater's replies to its client go out one per tick (the queue to the phone is short).
    uint8_t emitKind = 0; // 0 none, kota::U_NODE or kota::U_LIBENT
    size_t emitIdx = 0;
    uint8_t lastProgPhase = 0xFF;
    uint32_t lastProgBlock = 0xFFFFFFFF;
    bool heardOther = false;
    uint8_t health = 0; // 0 not needed, 1 waiting, 2 passed
    uint32_t healthStartMs = 0;
    uint32_t rebootAtMs = 0;
};

extern KotaModule *kotaModule;

#endif
