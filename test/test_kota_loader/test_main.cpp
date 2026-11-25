// koldnet SD loader (SPEC-0003 #ota-design item 6, TASK-20261125-02) on the host: a simulated card, app0,
// otadata and NVS, with the power cut at every step of an install and of a restore.
#include "TestUtil.h"
#include "configuration.h" // Arduino.h: setup() and loop() with C linkage
#include "mesh/koldnet/KotaLoader.h"
#include <Ed25519.h>
#include <SHA256.h>
#include <string.h>
#include <string>
#include <unity.h>
#include <vector>

using namespace kota;
typedef std::vector<uint8_t> Bytes;

void setUp(void) {}
void tearDown(void) {}

static const char ENV[] = "tlora-v2-1-1_6-tcxo";
static uint8_t PRIV[32], PUB[32];
static const uint8_t *const KEYS[1] = {PUB};

static void sha(const uint8_t *d, size_t n, uint8_t out[HASH])
{
    SHA256 h;
    h.update(d, n);
    h.finalize(out, HASH);
}

// An "image": magic, healthy flag, length, body, and a checksum so a half-written one does not verify.
static Bytes image(uint8_t seed, bool healthy, size_t len)
{
    Bytes b(len);
    for (size_t i = 0; i < len; i++)
        b[i] = (uint8_t)(seed * 31 + i * 7);
    b[0] = 0xE9;
    b[1] = healthy;
    b[2] = (uint8_t)len;
    b[3] = (uint8_t)(len >> 8);
    uint8_t s = 0;
    for (size_t i = 0; i + 1 < len; i++)
        s += b[i];
    b[len - 1] = s;
    return b;
}

static size_t imageLen(const Bytes &app)
{
    if (app.size() < 5 || app[0] != 0xE9)
        return 0;
    size_t len = app[2] | (app[3] << 8);
    if (len < 5 || len > app.size())
        return 0;
    uint8_t s = 0;
    for (size_t i = 0; i + 1 < len; i++)
        s += app[i];
    return s == app[len - 1] ? len : 0;
}

static void le32(Bytes &b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b.push_back((uint8_t)(v >> (8 * i)));
}

static Bytes manifest(const Bytes &img, uint16_t board = 2, const char *env = ENV, bool goodSig = true)
{
    Bytes b = {'K', 'O', 'T', 'A', 1, 0, (uint8_t)board, 0};
    le32(b, 2);
    le32(b, keyId(PUB));
    le32(b, (uint32_t)img.size());
    uint8_t h[HASH];
    sha(img.data(), img.size(), h);
    b.insert(b.end(), h, h + HASH);
    le32(b, 9); // the stream is not used here
    b.resize(152, 0x55);
    b.push_back((uint8_t)strlen(env));
    b.insert(b.end(), env, env + strlen(env));
    b.push_back(3);
    b.insert(b.end(), {'2', '.', '7'});
    uint8_t sig[64];
    Ed25519::sign(sig, PRIV, PUB, b.data(), b.size());
    if (!goodSig)
        sig[5] ^= 1;
    b.insert(b.end(), sig, sig + 64);
    return b;
}

enum Ota { O_NEW, O_PENDING, O_VALID, O_BAD };

struct Sim : public LoaderPlatform {
    bool haveCard = true, haveMan = false, haveImg = false, havePrev = false;
    Bytes man, img, prev, app;
    bool haveRec = false;
    LoaderRec rec;
    bool bootIsApp = true;
    Ota appOta = O_VALID;
    int budget = -1; // writes left before the power goes; -1: never
    bool dead = false;
    int writes = 0;

    Sim() { app.assign(3000, 0xFF); }
    bool spend() // false: the power is off from here on
    {
        if (dead)
            return false;
        writes++;
        if (budget > 0 && --budget == 0)
            dead = true;
        return !dead;
    }
    void setApp(const Bytes &b)
    {
        app.assign(3000, 0xFF);
        memcpy(app.data(), b.data(), b.size());
    }
    bool load(LoaderRec &r) override
    {
        if (haveRec)
            r = rec;
        return haveRec;
    }
    bool store(const LoaderRec &r) override
    {
        if (!spend())
            return false;
        rec = r;
        haveRec = true;
        return true;
    }
    AppState appState() override { return appOta == O_BAD ? AppState::BAD : AppState::OTHER; }
    bool appVerify(uint32_t &len) override
    {
        len = (uint32_t)imageLen(app);
        return len != 0;
    }
    bool appHash(uint32_t len, uint8_t out[HASH]) override
    {
        if (dead || len > app.size())
            return false;
        sha(app.data(), len, out);
        return true;
    }
    uint32_t appSlotSize() override { return (uint32_t)app.size(); }
    bool readManifest(uint8_t *buf, size_t max, size_t &len) override
    {
        if (!haveCard || !haveMan || man.size() > max)
            return false;
        len = man.size();
        memcpy(buf, man.data(), len);
        return true;
    }
    bool fileHash(LoaderFile w, uint32_t len, uint8_t out[HASH]) override
    {
        const Bytes &f = w == LoaderFile::IMAGE ? img : prev;
        if (dead || !haveCard || !(w == LoaderFile::IMAGE ? haveImg : havePrev) || f.size() != len)
            return false;
        sha(f.data(), len, out);
        return true;
    }
    bool copyAppToPrevious(uint32_t len, uint8_t out[HASH]) override
    {
        if (!haveCard)
            return false;
        havePrev = true;
        prev.assign(app.begin(), app.begin() + len / 2);
        if (!spend())
            return false;
        prev.assign(app.begin(), app.begin() + len);
        sha(prev.data(), len, out);
        return true;
    }
    bool copyToApp(LoaderFile w, uint32_t len) override
    {
        const Bytes f = w == LoaderFile::IMAGE ? img : prev;
        if (!haveCard || dead)
            return false;
        app.assign(app.size(), 0xFF); // erased
        for (size_t o = 0; o < len; o += 256) {
            if (!spend())
                return false;
            size_t n = len - o < 256 ? len - o : 256;
            memcpy(app.data() + o, f.data() + o, n);
        }
        return true;
    }
    bool bootApp(bool trusted) override
    {
        if (!imageLen(app) || !spend())
            return false;
        bootIsApp = true;
        appOta = trusted ? O_VALID : O_NEW;
        return true;
    }
    void log(const char *, unsigned) override {}

    // The app asks for an install, as KotaSdFlash::setBoot does.
    void ask(const Bytes &newImg, const Bytes &newMan)
    {
        img = newImg;
        man = newMan;
        haveImg = haveMan = true;
        rec.phase = LoaderPhase::IDLE;
        rec.haveWant = 1;
        sha(man.data(), man.size(), rec.want);
        haveRec = true;
        bootIsApp = false;
    }
    // The bootloader and the booted image, until an app has proved itself. The last action the loader took.
    bool settle(int maxBoots = 30)
    {
        for (int i = 0; i < maxBoots; i++) {
            dead = false;
            budget = i == 0 ? budget : -1;
            if (bootIsApp && appOta == O_NEW) {
                appOta = O_PENDING;
                if (!imageLen(app))
                    return false; // never: an unverified image was set to boot
                if (app[1]) {
                    appOta = O_VALID;
                    return true;
                }
                appOta = O_BAD; // health failed, reset, the bootloader falls back
                bootIsApp = false;
                continue;
            }
            if (bootIsApp && appOta == O_VALID)
                return imageLen(app) != 0;
            KotaLoader l(*this, 2, ENV, KEYS, 1);
            l.run();
        }
        return false;
    }
    bool runs(const Bytes &b) { return memcmp(app.data(), b.data(), b.size()) == 0; }
};

static Bytes OLD, GOOD, SICK;

static void test_install_and_previous_kept()
{
    Sim s;
    s.setApp(OLD);
    s.ask(GOOD, manifest(GOOD));
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(GOOD));
    TEST_ASSERT_TRUE(s.prev == OLD);
    TEST_ASSERT_EQUAL((int)LoaderResult::INSTALLED, (int)s.rec.result);
    TEST_ASSERT_EQUAL(0, s.rec.haveWant);
}

static void test_failed_health_restores_previous()
{
    Sim s;
    s.setApp(OLD);
    s.ask(SICK, manifest(SICK));
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(OLD));
    TEST_ASSERT_EQUAL((int)LoaderResult::RESTORED, (int)s.rec.result);
    s.ask(GOOD, manifest(GOOD)); // and the next one still installs
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(GOOD));
}

static void refused(Sim &s, uint8_t detail)
{
    Bytes before = s.app;
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.app == before);
    TEST_ASSERT_EQUAL((int)LoaderResult::REFUSED, (int)s.rec.result);
    TEST_ASSERT_EQUAL_HEX8(detail, s.rec.detail);
    TEST_ASSERT_EQUAL((int)O_VALID, (int)s.appOta);
    TEST_ASSERT_FALSE(s.havePrev); // not even the copy was started
}

// Acceptance 8: a byte changed on the card after the app verified it.
static void test_tampered_card_is_refused()
{
    Sim a;
    a.setApp(OLD);
    a.ask(GOOD, manifest(GOOD));
    a.img[900] ^= 1;
    refused(a, (uint8_t)Err::HASH_MISMATCH);
    Sim b;
    b.setApp(OLD);
    b.ask(GOOD, manifest(GOOD));
    b.man[10] ^= 1;
    refused(b, 0x82);
    Sim c; // both files replaced by another signed image: not the one the app accepted
    c.setApp(OLD);
    c.ask(GOOD, manifest(GOOD));
    c.img = SICK;
    c.man = manifest(SICK);
    refused(c, 0x82);
    Sim d;
    d.setApp(OLD);
    d.ask(GOOD, manifest(GOOD, 2, ENV, false));
    refused(d, (uint8_t)Err::SIGNATURE);
    Sim e;
    e.setApp(OLD);
    e.ask(GOOD, manifest(GOOD, 1));
    refused(e, (uint8_t)Err::BOARD);
    Sim f;
    f.setApp(OLD);
    f.ask(GOOD, manifest(GOOD, 2, "heltec-v3"));
    refused(f, (uint8_t)Err::ENV);
    Sim g;
    g.setApp(OLD);
    g.ask(GOOD, manifest(GOOD));
    g.img.pop_back();
    refused(g, 0x83);
    Sim h;
    h.setApp(OLD);
    h.ask(GOOD, manifest(GOOD));
    h.haveCard = false;
    refused(h, 0x81);
}

static void test_power_cut_at_every_write_of_an_install()
{
    int cuts = 0;
    for (int cut = 1; cut < 200; cut++) {
        Sim s;
        s.setApp(OLD);
        s.ask(GOOD, manifest(GOOD));
        s.budget = cut;
        TEST_ASSERT_TRUE_MESSAGE(s.settle(), "stuck after a power cut");
        TEST_ASSERT_TRUE_MESSAGE(s.runs(GOOD), "the install was not finished");
        if (s.writes < cut)
            break;
        cuts++;
    }
    TEST_ASSERT_GREATER_THAN(8, cuts);
}

static void test_power_cut_at_every_write_of_a_restore()
{
    int cuts = 0;
    for (int cut = 1; cut < 200; cut++) {
        Sim s;
        s.setApp(OLD);
        s.ask(SICK, manifest(SICK));
        KotaLoader(s, 2, ENV, KEYS, 1).run(); // installed, set to boot
        TEST_ASSERT_TRUE(s.bootIsApp);
        s.appOta = O_BAD;
        s.bootIsApp = false;
        s.writes = 0;
        s.budget = cut;
        TEST_ASSERT_TRUE_MESSAGE(s.settle(), "stuck after a power cut");
        TEST_ASSERT_TRUE_MESSAGE(s.runs(OLD), "the previous image is not back");
        if (s.writes < cut)
            break;
        cuts++;
    }
    TEST_ASSERT_GREATER_THAN(5, cuts);
}

static void test_power_cut_while_installing_a_bad_image_ends_on_the_old_one()
{
    for (int cut = 1; cut < 60; cut++) {
        Sim s;
        s.setApp(OLD);
        s.ask(SICK, manifest(SICK));
        s.budget = cut;
        TEST_ASSERT_TRUE_MESSAGE(s.settle(), "stuck after a power cut");
        TEST_ASSERT_TRUE_MESSAGE(s.runs(OLD), "not back on the old image");
    }
}

static void test_card_lost_during_the_write_restores_or_waits()
{
    Sim s;
    s.setApp(OLD);
    s.ask(GOOD, manifest(GOOD));
    s.budget = 8; // in the middle of the app0 write
    KotaLoader(s, 2, ENV, KEYS, 1).run();
    TEST_ASSERT_TRUE(s.dead);
    s.dead = false;
    s.budget = -1;
    s.haveCard = false;
    TEST_ASSERT_EQUAL((int)LoaderAction::WAIT, (int)KotaLoader(s, 2, ENV, KEYS, 1).run());
    TEST_ASSERT_FALSE(s.bootIsApp); // a half-written app0 is never set to boot
    s.haveCard = true;
    s.img[7] ^= 1; // the new image rotted meanwhile: the previous one comes back
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(OLD));
}

static void test_nothing_asked_boots_the_app()
{
    Sim s;
    s.setApp(OLD);
    s.bootIsApp = false;
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(OLD));
}

static void test_a_signed_image_that_is_not_bootable_restores()
{
    Sim s;
    s.setApp(OLD);
    Bytes junk = GOOD;
    junk[junk.size() - 1] ^= 1;
    s.ask(junk, manifest(junk));
    TEST_ASSERT_TRUE(s.settle());
    TEST_ASSERT_TRUE(s.runs(OLD));
}

void setup()
{
    initializeTestEnvironment();
    sha((const uint8_t *)"koldnet KOTA throwaway test key v1", 34, PRIV);
    Ed25519::derivePublicKey(PUB, PRIV);
    OLD = image(1, true, 1500);
    GOOD = image(2, true, 2200);
    SICK = image(3, false, 2100);
    UNITY_BEGIN();
    RUN_TEST(test_install_and_previous_kept);
    RUN_TEST(test_failed_health_restores_previous);
    RUN_TEST(test_tampered_card_is_refused);
    RUN_TEST(test_power_cut_at_every_write_of_an_install);
    RUN_TEST(test_power_cut_at_every_write_of_a_restore);
    RUN_TEST(test_power_cut_while_installing_a_bad_image_ends_on_the_old_one);
    RUN_TEST(test_card_lost_during_the_write_restores_or_waits);
    RUN_TEST(test_nothing_asked_boots_the_app);
    RUN_TEST(test_a_signed_image_that_is_not_bootable_restores);
    exit(UNITY_END());
}

void loop() {}
