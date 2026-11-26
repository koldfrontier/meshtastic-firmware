// koldnet OTA, ESP32 glue (SPEC-0003 #ota-local). See KotaModule.h.
#include "KotaModule.h"

#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_KOTA

#include "MeshService.h"
#include "NodeDB.h"
#include "RadioLibInterface.h"
#include "Router.h"
#include "main.h"
#include "KotaSdFlash.h"
#include "mesh/koldnet/KotaSender.h"
#if KOLDNET_UPDATER
#include <SD.h>
#include "concurrency/LockGuard.h"
#endif
#include <Ed25519.h>
#include <SHA256.h>
#include <esp_ota_ops.h>
#include <string.h>

#ifndef KOLDNET_RELEASE
#define KOLDNET_RELEASE 0 // a USB build; a release build sets it (SPEC-0003 #ota-format)
#endif
#ifndef KOLDNET_KOTA_HEALTH_S
#define KOLDNET_KOTA_HEALTH_S 900
#endif
#ifndef KOLDNET_KOTA_TEST_KEY
#define KOLDNET_KOTA_TEST_KEY 0
#endif
#ifndef KOLDNET_KOTA_TEST_FAIL_HEALTH
#define KOLDNET_KOTA_TEST_FAIL_HEALTH 0
#endif
#ifndef KOLDNET_KOTA_QUERY_JITTER_MS
#define KOLDNET_KOTA_QUERY_JITTER_MS 1500 // the longest random wait before a STATUS that answers a QUERY
#endif
// The field updater (SPEC-0003 #ota-updater, U1): a library on the SD card and the K2a sender on this node.
#ifndef KOLDNET_UPDATER
#define KOLDNET_UPDATER 0
#endif

// K2a (SPEC-0003 #ota-mesh): take an install broadcast by another node over LoRa. Until INSTALL under admin
// PKI exists (the Key phase) only test builds do: a node on the channel could make this node reboot.
#ifndef KOLDNET_KOTA_RADIO
#define KOLDNET_KOTA_RADIO KOLDNET_KOTA_TEST_KEY
#endif

#if defined(HELTEC_V3)
#define KOLDNET_BOARD_ID 1
#elif defined(TLORA_V2_1_16)
#define KOLDNET_BOARD_ID 2
#elif defined(T_BEAM_1W)
#define KOLDNET_BOARD_ID 3
#else
#define KOLDNET_BOARD_ID 0 // not a koldnet board (config/ids.yaml): no image can match
#endif

KotaModule *kotaModule;

// The release key (SPEC-0003 #ota-key; SHA-256 1318475a10514f3e...).
static const uint8_t RELEASE_KEY[32] = {0xbf, 0x32, 0x2a, 0x58, 0xc1, 0xdc, 0x7e, 0x3c, 0xd4, 0x2f, 0xa5,
                                        0xaa, 0x09, 0x17, 0x0a, 0xea, 0xc9, 0xb5, 0x6c, 0x44, 0xb8, 0x07,
                                        0x25, 0x1f, 0xf1, 0xac, 0x4d, 0x77, 0xe6, 0x63, 0xb1, 0xb1};
#if KOLDNET_KOTA_TEST_KEY
// The throwaway test key of scripts/kota.py: anyone can sign with it. Test builds only.
static const char TEST_SEED_TEXT[] = "koldnet KOTA throwaway test key v1";
static uint8_t testKey[32];
#endif

namespace
{
#if !KOLDNET_KOTA_SD
class EspFlash : public kota::Flash
{
  public:
    uint32_t spareSize() override
    {
        const esp_partition_t *p = esp_ota_get_next_update_partition(NULL);
        return p ? p->size : 0;
    }
    bool begin(uint32_t size) override
    {
        part = esp_ota_get_next_update_partition(NULL);
        if (!part || size > part->size)
            return false;
        return esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &h) == ESP_OK;
    }
    bool write(const uint8_t *d, size_t n) override { return esp_ota_write(h, d, n) == ESP_OK; }
    bool end() override
    {
        esp_err_t e = esp_ota_end(h); // also checks the image header and its appended SHA-256
        h = 0;
        if (e != ESP_OK)
            LOG_ERROR("KOTA: esp_ota_end %s", esp_err_to_name(e));
        return e == ESP_OK;
    }
    bool setBoot() override { return part && esp_ota_set_boot_partition(part) == ESP_OK; }
    void abort() override
    {
        if (h)
            esp_ota_abort(h);
        h = 0;
    }

  private:
    const esp_partition_t *part = nullptr;
    esp_ota_handle_t h = 0;
};
#endif

#if KOLDNET_KOTA_SD
KotaSdFlash espFlash; // staged on the card, installed by the loader in ota_1
#else
EspFlash espFlash;
#endif
kota::Identity identity;
kota::Installer *installer;

#if KOLDNET_UPDATER
// The card as the library sees it. On the T-Beam it is on the radio's SPI bus (FSCommon mounts it at boot),
// so every access takes spiLock; on the LoRa32 it has its own HSPI bus (KotaSdFlash).
#if KOLDNET_KOTA_SD
#define UPD_LOCK()
#else
#define UPD_LOCK() concurrency::LockGuard g(spiLock)
#endif
class SdStorage : public kota::Storage
{
  public:
    bool ready()
    {
#if KOLDNET_KOTA_SD
        return espFlash.mountCard();
#else
        UPD_LOCK();
        return SD.cardType() != CARD_NONE;
#endif
    }
    size_t listDirs(const char *path, char (*names)[kota::LIB_NAME], size_t max) override
    {
        UPD_LOCK();
        closeCur();
        File d = SD.open(path);
        if (!d || !d.isDirectory())
            return 0;
        size_t n = 0;
        for (File f = d.openNextFile(); f && n < max; f = d.openNextFile()) {
            if (f.isDirectory()) {
                const char *nm = f.name();
                const char *b = strrchr(nm, '/');
                b = b ? b + 1 : nm;
                strncpy(names[n], b, kota::LIB_NAME - 1);
                names[n][kota::LIB_NAME - 1] = 0;
                n++;
            }
            f.close();
        }
        d.close();
        for (size_t i = 1; i < n; i++) // by name, so an index means the same image after a rescan
            for (size_t j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--) {
                char t[kota::LIB_NAME];
                memcpy(t, names[j], sizeof t);
                memcpy(names[j], names[j - 1], sizeof t);
                memcpy(names[j - 1], t, sizeof t);
            }
        return n;
    }
    int32_t size(const char *path) override
    {
        UPD_LOCK();
        File f = SD.open(path);
        if (!f)
            return -1;
        int32_t s = f.isDirectory() ? -1 : (int32_t)f.size();
        f.close();
        return s;
    }
    bool read(const char *path, uint32_t off, uint8_t *buf, size_t n) override
    {
        UPD_LOCK();
        if (!cur || strcmp(curPath, path) != 0) {
            closeCur();
            cur = SD.open(path);
            if (!cur)
                return false;
            strncpy(curPath, path, sizeof curPath - 1);
        }
        if (!cur.seek(off))
            return false;
        return cur.read(buf, n) == (int)n;
    }

  private:
    void closeCur()
    {
        if (cur)
            cur.close();
        curPath[0] = 0;
    }
    File cur;
    char curPath[kota::LIB_NAME + 32] = {};
};

class UpdaterRadio : public kota::RadioOut
{
  public:
    bool ready() override
    {
        RadioInterface *r = RadioLibInterface::instance; // the base class: its queue status is public
        return r && r->getQueueStatus().free > 8; // never fill the 16-packet queue (kota_mesh.py)
    }
    bool send(const uint8_t *f, size_t n) override
    {
        kotaModule->sendRadio(f, n);
        return true;
    }
    uint32_t airtimeMs(size_t n) override
    {
        RadioInterface *r = RadioLibInterface::instance; // the base class: its queue status is public
        return r ? r->getPacketTime((uint32_t)(n + 8 + 16)) : 100; // the 16-byte header and the protobuf
    }
};

SdStorage storage;
UpdaterRadio updaterRadio;
kota::Sender *sender;
kota::Library library;
kota::LibSource *source;
#endif

uint8_t slotOf(const esp_partition_t *p)
{
    if (!p)
        return 0xFF;
    if (p->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN && p->subtype < ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
        return (uint8_t)(p->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN);
    return 0xFE; // factory
}
} // namespace

// Arduino marks a PENDING_VERIFY image valid before setup() unless this returns true
// (esp32-hal-misc.c initArduino). The weak default is C, so the override needs C linkage.
extern "C" bool verifyRollbackLater()
{
    return true;
}

KotaModule::KotaModule() : MeshModule("kota"), concurrency::OSThread("kota")
{
    isPromiscuous = true; // to see that another node was heard, for the health check
    identity.boardId = KOLDNET_BOARD_ID;
    identity.env = optstr(APP_ENV); // the same string as my_info.pio_env (PhoneAPI.cpp)
    identity.release = KOLDNET_RELEASE;
    identity.keys[0] = RELEASE_KEY;
    identity.keyCount = 1;
#if KOLDNET_KOTA_TEST_KEY
    uint8_t priv[32];
    SHA256 sh;
    sh.update(TEST_SEED_TEXT, strlen(TEST_SEED_TEXT));
    sh.finalize(priv, sizeof priv);
    Ed25519::derivePublicKey(testKey, priv);
    identity.keys[1] = testKey;
    identity.keyCount = 2;
#endif
    installer = new kota::Installer(espFlash, identity);
#if KOLDNET_UPDATER
    sender = new kota::Sender(updaterRadio);
#endif
#if KOLDNET_KOTA_SD
    espFlash.attach(installer);
    espFlash.logLoaderResult();
#endif

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    bool pending = esp_ota_get_state_partition(running, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY;
    if (pending) {
        health = 1;
        healthStartMs = millis();
    }
    LOG_INFO("KOTA: %s env %s release %u board %u slot ota_%u %s, test key %d", optstr(APP_VERSION), identity.env,
             (unsigned)identity.release, (unsigned)identity.boardId, slotOf(running),
             pending ? "PENDING_VERIFY (health check running)" : "not pending", KOLDNET_KOTA_TEST_KEY);
}

bool KotaModule::handleLocal(const meshtastic_MeshPacket &p)
{
    if (p.which_payload_variant != meshtastic_MeshPacket_decoded_tag || p.decoded.portnum != (meshtastic_PortNum)kota::PORT)
        return false;
    if (!isToUs(&p))
        return false; // port 333 to another node goes out as a normal packet (the mesh frames are K2)
    if (p.decoded.payload.size && p.decoded.payload.bytes[0] >= kota::U_SCAN && p.decoded.payload.bytes[0] < 0x70) {
        handleUpdater(p.decoded.payload.bytes, p.decoded.payload.size);
        setIntervalFromNow(0);
        return true;
    }
    kota::Reply r = installer->handle(p.decoded.payload.bytes, p.decoded.payload.size, millis());
    uint8_t buf[100];
    size_t n = answer(r, buf, sizeof buf);
    if (n)
        reply(buf, n);
    setIntervalFromNow(0);
    return true;
}

size_t KotaModule::answer(kota::Reply r, uint8_t *buf, size_t max)
{
    size_t n = 0;
    if (r == kota::Reply::BLOCK) {
        n = installer->encodeBlock(buf, max);
    } else if (r == kota::Reply::STATUS) {
        kota::PlatformStatus ps;
        fillStatus(ps);
        n = installer->encodeStatus(ps, buf, max);
        if (installer->state() == kota::State::FAILED)
            LOG_WARN("KOTA: install refused, error 0x%02x", installer->error());
        if (installer->state() == kota::State::DONE) {
            LOG_INFO("KOTA: image %s release %u written and set to boot", installer->manifest().version,
                     (unsigned)installer->manifest().release);
            if (installer->rebootRequested() && !rebootAtMs)
                rebootAtMs = millis() + 8000; // time for the answer to leave over LoRa
        }
    }
    return n;
}

void KotaModule::replyRadio(const uint8_t *buf, size_t len, uint8_t channel)
{
    meshtastic_MeshPacket *p = router->allocForSending();
    if (!p)
        return;
    p->to = NODENUM_BROADCAST; // the channel key: a unicast would need PKI, which the sender may not have
    p->channel = channel;
    p->decoded.portnum = (meshtastic_PortNum)kota::PORT;
    p->want_ack = false;
    p->hop_limit = 0;
    memcpy(p->decoded.payload.bytes, buf, len);
    p->decoded.payload.size = len;
    service->sendToMesh(p);
}

void KotaModule::reply(const uint8_t *buf, size_t len)
{
    meshtastic_MeshPacket *p = router->allocForSending();
    if (!p)
        return;
    p->to = nodeDB->getNodeNum();
    p->decoded.portnum = (meshtastic_PortNum)kota::PORT;
    p->want_ack = false;
    memcpy(p->decoded.payload.bytes, buf, len);
    p->decoded.payload.size = len;
    service->handleFromRadio(p); // to the local clients only
    packetPool.release(p);
}

void KotaModule::fillStatus(kota::PlatformStatus &ps)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    ps.runningSlot = slotOf(running);
    ps.bootSlot = slotOf(esp_ota_get_boot_partition());
    esp_ota_img_states_t st;
    ps.imageState = esp_ota_get_state_partition(running, &st) == ESP_OK ? (uint8_t)st : 0xFF;
    ps.health = health;
    ps.testKey = KOLDNET_KOTA_TEST_KEY;
    const esp_app_desc_t *d = esp_ota_get_app_description();
    if (d)
        memcpy(ps.elfSha, d->app_elf_sha256, 8);
    ps.version = optstr(APP_VERSION);
}

ProcessMessage KotaModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA && !isFromUs(&mp))
        heardOther = true;
#if KOLDNET_KOTA_RADIO
    if (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA && !isFromUs(&mp) &&
        mp.which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
        mp.decoded.portnum == (meshtastic_PortNum)kota::PORT && isBroadcast(mp.to)) {
        kota::Reply r =
            installer->handleRadio(getFrom(&mp), mp.decoded.payload.bytes, mp.decoded.payload.size, millis());
        uint8_t buf[100];
        size_t n = answer(r, buf, sizeof buf);
        if (n && mp.decoded.payload.bytes[0] == kota::L_QUERY && KOLDNET_KOTA_QUERY_JITTER_MS > 0) {
            memcpy(pendingBuf, buf, n);
            pendingLen = n;
            pendingChannel = mp.channel;
            uint32_t wait = (uint32_t)random(0, KOLDNET_KOTA_QUERY_JITTER_MS);
            pendingAtMs = millis() + wait;
            setIntervalFromNow(wait);
        } else if (n) {
            replyRadio(buf, n, mp.channel);
        }
        // Image frames are not for this node's clients; replies (0x50 up) are.
        if (mp.decoded.payload.size && mp.decoded.payload.bytes[0] >= kota::L_MANIFEST &&
            mp.decoded.payload.bytes[0] <= kota::L_QUERY)
            return ProcessMessage::STOP;
    }
#endif
#if KOLDNET_UPDATER
    // Replies to this node's sender (STATUS, BLOCK).
    if (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA && !isFromUs(&mp) &&
        mp.which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
        mp.decoded.portnum == (meshtastic_PortNum)kota::PORT && mp.decoded.payload.size &&
        (mp.decoded.payload.bytes[0] == kota::L_STATUS || mp.decoded.payload.bytes[0] == kota::L_BLOCK)) {
        sender->onReply(getFrom(&mp), mp.decoded.payload.bytes, mp.decoded.payload.size, (int16_t)mp.rx_rssi,
                        (int16_t)(mp.rx_snr * 4), millis());
        setIntervalFromNow(0);
    }
#endif
    return ProcessMessage::CONTINUE;
}

int32_t KotaModule::runOnce()
{
    uint32_t now = millis();
    installer->tick(now);
    uint32_t wait = 1000;
    if (pendingLen) {
        if ((int32_t)(now - pendingAtMs) >= 0) {
            replyRadio(pendingBuf, pendingLen, pendingChannel);
            pendingLen = 0;
        } else {
            wait = pendingAtMs - now;
        }
    }
#if KOLDNET_UPDATER
    uint32_t w = updaterStep(now);
    if (w < wait)
        wait = w;
#endif
    if (rebootAtMs && (int32_t)(now - rebootAtMs) >= 0) {
        LOG_INFO("KOTA: rebooting into the new image");
        delay(100);
        ESP.restart();
    }
    if (health == 1) {
        bool radioUp = RadioLibInterface::instance != nullptr;
        bool ok = radioUp && heardOther && !KOLDNET_KOTA_TEST_FAIL_HEALTH;
        if (ok) {
            esp_ota_mark_app_valid_cancel_rollback();
            health = 2;
            LOG_INFO("KOTA: health check passed after %u s, image marked valid", (unsigned)((now - healthStartMs) / 1000));
        } else if (now - healthStartMs > (uint32_t)KOLDNET_KOTA_HEALTH_S * 1000) {
            LOG_ERROR("KOTA: health check failed (radio %d, heard %d, test fail %d) after %u s; restarting for rollback",
                      radioUp, heardOther, KOLDNET_KOTA_TEST_FAIL_HEALTH, (unsigned)KOLDNET_KOTA_HEALTH_S);
            delay(100);
            ESP.restart(); // still PENDING_VERIFY: the bootloader starts the previous image
        }
    }
    return wait;
}

void KotaModule::ack(uint8_t cmd, uint8_t result, uint8_t extra)
{
    uint8_t b[4] = {kota::U_ACK, cmd, result, extra};
    reply(b, sizeof b);
}

#if KOLDNET_UPDATER
static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

void KotaModule::handleUpdater(const uint8_t *b, size_t n)
{
    uint8_t cmd = b[0];
    uint32_t now = millis();
    switch (cmd) {
    case kota::U_SCAN: {
        uint8_t rounds = n > 1 ? b[1] : 3;
        uint32_t roundMs = n > 3 ? rd16le(b + 2) : 4000;
        bool ok = sender->scan(rounds, roundMs, now);
        ack(cmd, ok ? 0 : (uint8_t)kota::UErr::BUSY);
        if (ok)
            LOG_INFO("KOTA updater: scan, %u rounds of %u ms", rounds, (unsigned)roundMs);
        break;
    }
    case kota::U_HEARD:
        ack(cmd, 0, (uint8_t)sender->heardCount());
        emitKind = kota::U_NODE;
        emitIdx = 0;
        break;
    case kota::U_LIB: {
        if (sender->busy()) {
            ack(cmd, (uint8_t)kota::UErr::BUSY);
            break;
        }
        if (!storage.ready()) {
            ack(cmd, (uint8_t)kota::UErr::NO_STORAGE);
            break;
        }
        size_t c = library.scan(storage, identity.keys, identity.keyCount);
        LOG_INFO("KOTA updater: library has %u images", (unsigned)c);
        ack(cmd, 0, (uint8_t)c);
        emitKind = kota::U_LIBENT;
        emitIdx = 0;
        break;
    }
    case kota::U_PUSH: {
        // [image u8][load permille u16][block timeout ms u16][n u8][node u32 x n]
        if (n < 7 || n < 7u + 4u * b[6]) {
            ack(cmd, (uint8_t)kota::UErr::BAD_FRAME);
            break;
        }
        if (sender->busy()) {
            ack(cmd, (uint8_t)kota::UErr::BUSY);
            break;
        }
        uint8_t img = b[1];
        if (img >= library.count() || library.entry(img).err != 0) {
            ack(cmd, (uint8_t)kota::UErr::NO_IMAGE);
            break;
        }
        uint32_t nodes[kota::MAX_TARGETS];
        size_t k = b[6] < kota::MAX_TARGETS ? b[6] : kota::MAX_TARGETS;
        for (size_t i = 0; i < k; i++) {
            const uint8_t *q = b + 7 + 4 * i;
            nodes[i] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
        }
        kota::SenderConfig c;
        uint16_t load = rd16le(b + 2), bt = rd16le(b + 4);
        if (load)
            c.loadPermille = load;
        if (bt)
            c.blockTimeoutMs = bt;
        delete source;
        source = new kota::LibSource(storage, library.entry(img));
        bool ok = k > 0 && sender->push(source, nodes, k, c, now);
        ack(cmd, ok ? 0 : (uint8_t)(k ? kota::UErr::NO_IMAGE : kota::UErr::NO_TARGET));
        if (ok)
            LOG_INFO("KOTA updater: push %s r%u to %u nodes", library.entry(img).name,
                     (unsigned)library.entry(img).m.release, (unsigned)k);
        break;
    }
    case kota::U_PROGRESS: {
        uint8_t o[100];
        size_t len = sender->encodeProgress(now, o, sizeof o);
        if (len)
            reply(o, len);
        break;
    }
    case kota::U_CANCEL:
        sender->cancel();
        ack(cmd, 0);
        break;
    default:
        ack(cmd, (uint8_t)kota::UErr::BAD_FRAME);
    }
}

uint32_t KotaModule::updaterStep(uint32_t now)
{
    uint32_t w = sender->step(now);
    for (int k = 0; w == 0 && k < 8; k++)
        w = sender->step(now);
    // Progress to the client when the phase changes and every 10 blocks; a client that left misses nothing.
    if (sender->phase() != (kota::Phase)lastProgPhase ||
        (sender->phase() == kota::Phase::DATA && sender->block() != lastProgBlock && sender->block() % 10 == 0)) {
        uint8_t o[100];
        size_t len = sender->encodeProgress(now, o, sizeof o);
        if (len)
            reply(o, len);
        if (sender->phase() != (kota::Phase)lastProgPhase)
            LOG_INFO("KOTA updater: phase %u, block %u of %u, resent %u, why %u", (unsigned)sender->phase(),
                     (unsigned)sender->block(), (unsigned)sender->blocks(), (unsigned)sender->resent(),
                     (unsigned)sender->why());
        lastProgPhase = (uint8_t)sender->phase();
        lastProgBlock = sender->block();
    }
    if (emitKind) {
        uint8_t o[160];
        size_t len = emitKind == kota::U_NODE ? kota::encodeNode(*sender, emitIdx, now, o, sizeof o)
                                              : kota::encodeLibEntry(library, emitIdx, o, sizeof o);
        if (len) {
            reply(o, len);
            emitIdx++;
        } else {
            emitKind = 0;
        }
        if (w > 60)
            w = 60;
    }
    return w ? w : 1;
}
#else
void KotaModule::handleUpdater(const uint8_t *b, size_t n)
{
    (void)n;
    ack(b[0], (uint8_t)kota::UErr::OFF); // not an updater build
}
#endif

#endif
