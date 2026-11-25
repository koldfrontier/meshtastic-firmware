#include "KotaLoader.h"

#include <string.h>

namespace kota
{

LoaderAction loaderDecide(const LoaderFacts &f)
{
    switch (f.phase) {
    case LoaderPhase::WRITING:
        if (f.appBad) // written, booted and failed before the record said TRIAL: do not install it again
            return f.prevOk ? LoaderAction::RESTORE : f.appOk ? LoaderAction::BOOT_APP : LoaderAction::WAIT;
        if (f.wanted && f.cardOk)
            return LoaderAction::INSTALL; // power was lost while app0 was written
        return f.prevOk ? LoaderAction::RESTORE : LoaderAction::WAIT;
    case LoaderPhase::RESTORING:
        return f.prevOk ? LoaderAction::RESTORE : f.appOk ? LoaderAction::BOOT_APP : LoaderAction::WAIT;
    case LoaderPhase::TRIAL:
        if (f.appBad)
            return f.prevOk ? LoaderAction::RESTORE : f.appOk ? LoaderAction::BOOT_APP : LoaderAction::WAIT;
        break; // the trial passed: as IDLE
    case LoaderPhase::IDLE:
        break;
    }
    if (f.wanted && f.cardOk)
        return LoaderAction::INSTALL;
    if (f.appOk)
        return LoaderAction::BOOT_APP;
    return f.prevOk ? LoaderAction::RESTORE : LoaderAction::WAIT;
}

uint8_t KotaLoader::checkCard(const LoaderRec &r, Manifest &m)
{
    uint8_t man[MAX_MANIFEST];
    size_t len = 0;
    if (!p.readManifest(man, sizeof man, len))
        return 0x81;
    SHA256 h;
    uint8_t sha[HASH];
    h.update(man, len);
    h.finalize(sha, HASH);
    if (memcmp(sha, r.want, HASH) != 0)
        return 0x82; // not the manifest the app accepted
    Manifest parsed;
    Err e = parse(man, len, parsed);
    if (e != Err::OK)
        return (uint8_t)e;
    e = Err::KEY_ID;
    for (size_t i = 0; i < keyCount && e != Err::OK; i++)
        e = verify(man, len, keys[i], m);
    if (e != Err::OK)
        return (uint8_t)e;
    if (m.boardId != boardId)
        return (uint8_t)Err::BOARD;
    if (strcmp(m.env, env) != 0)
        return (uint8_t)Err::ENV;
    if (m.rawSize > p.appSlotSize())
        return (uint8_t)Err::SIZE;
    if (!p.fileHash(LoaderFile::IMAGE, m.rawSize, sha))
        return 0x83;
    return memcmp(sha, m.rawSha, HASH) == 0 ? 0 : (uint8_t)Err::HASH_MISMATCH;
}

bool KotaLoader::prevGood(const LoaderRec &r)
{
    uint8_t sha[HASH];
    return r.prevLen && r.prevLen <= p.appSlotSize() && p.fileHash(LoaderFile::PREVIOUS, r.prevLen, sha) &&
           memcmp(sha, r.prevSha, HASH) == 0;
}

LoaderAction KotaLoader::run()
{
    LoaderRec r;
    if (!p.load(r) || r.version != LOADER_REC_VERSION)
        r = LoaderRec();
    LoaderFacts f = {};
    Manifest m;
    f.phase = r.phase;
    f.wanted = r.haveWant != 0;
    f.appBad = p.appState() == AppState::BAD;
    uint32_t appLen = 0;
    f.appOk = p.appVerify(appLen);
    uint8_t cardErr = 0xFF;
    if (f.wanted) {
        cardErr = checkCard(r, m);
        f.cardOk = cardErr == 0;
    }
    f.prevOk = prevGood(r);
    p.log("phase", (unsigned)r.phase);
    p.log("install asked", f.wanted);
    p.log("card check", cardErr);
    p.log("app0 image good", f.appOk);
    p.log("app0 marked bad", f.appBad);
    p.log("previous image good", f.prevOk);
    switch (loaderDecide(f)) {
    case LoaderAction::INSTALL:
        return install(r, m, f.appOk, appLen);
    case LoaderAction::RESTORE:
        return restore(r);
    case LoaderAction::BOOT_APP:
        return f.wanted ? bootOld(r, LoaderResult::REFUSED, cardErr) : bootOld(r, r.result, r.detail);
    case LoaderAction::WAIT:
        break;
    }
    p.log("nothing to boot, waiting", 0);
    return LoaderAction::WAIT;
}

LoaderAction KotaLoader::bootOld(LoaderRec &r, LoaderResult res, uint8_t detail)
{
    r.phase = LoaderPhase::IDLE;
    r.haveWant = 0;
    r.result = res;
    r.detail = detail;
    p.log("app0 left as it is, result", (unsigned)res);
    if (!p.bootApp(true))
        return LoaderAction::WAIT;
    p.store(r);
    return LoaderAction::BOOT_APP;
}

LoaderAction KotaLoader::install(LoaderRec &r, const Manifest &m, bool appOk, uint32_t appLen)
{
    if (r.phase != LoaderPhase::WRITING) {
        if (appOk) { // keep what runs now; the old copy is void from the first byte
            r.prevLen = 0;
            uint8_t sha[HASH], back[HASH];
            if (!p.store(r) || !p.copyAppToPrevious(appLen, sha) || !p.fileHash(LoaderFile::PREVIOUS, appLen, back) ||
                memcmp(sha, back, HASH) != 0)
                return bootOld(r, LoaderResult::NO_PREVIOUS_COPY, 0);
            r.prevLen = appLen;
            memcpy(r.prevSha, sha, HASH);
        }
        r.phase = LoaderPhase::WRITING;
        if (!p.store(r)) {
            return LoaderAction::WAIT; // app0 is untouched
        }
    }
    p.log("writing app0, bytes", m.rawSize);
    uint8_t sha[HASH];
    if (!p.copyToApp(LoaderFile::IMAGE, m.rawSize) || !p.appHash(m.rawSize, sha) || memcmp(sha, m.rawSha, HASH) != 0) {
        p.log("app0 does not read back, will retry", 0);
        return LoaderAction::WAIT;
    }
    if (!p.bootApp(false)) {
        p.log("the image does not boot", 0);
        return prevGood(r) ? restore(r) : LoaderAction::WAIT;
    }
    r.phase = LoaderPhase::TRIAL;
    r.haveWant = 0;
    r.result = LoaderResult::INSTALLED;
    r.detail = 0;
    p.store(r);
    p.log("installed, bytes", m.rawSize);
    return LoaderAction::INSTALL;
}

LoaderAction KotaLoader::restore(LoaderRec &r)
{
    r.phase = LoaderPhase::RESTORING;
    r.haveWant = 0;
    if (!p.store(r))
        return LoaderAction::WAIT;
    p.log("restoring the previous image, bytes", r.prevLen);
    uint8_t sha[HASH];
    if (!p.copyToApp(LoaderFile::PREVIOUS, r.prevLen) || !p.appHash(r.prevLen, sha) || memcmp(sha, r.prevSha, HASH) != 0 ||
        !p.bootApp(true))
        return LoaderAction::WAIT;
    r.phase = LoaderPhase::IDLE;
    r.result = LoaderResult::RESTORED;
    r.detail = 0;
    p.store(r);
    return LoaderAction::RESTORE;
}

} // namespace kota
