// koldnet forced routes: the destination side (SPEC-0002 #interfaces).
#include "KRouteModule.h"

#if !MESHTASTIC_EXCLUDE_KROUTE

#include "MeshService.h"
#include "NodeDB.h"
#include "Router.h"
#include "configuration.h"
#include "main.h"
#include <string.h>

KRouteModule *krouteModule;

#if KOLDNET_TEST_LINKS
kroute::LinkFilter krouteTestLinks;
#endif

bool krouteDecodeRouted(const meshtastic_MeshPacket *p, kroute::Routed *r)
{
    if (p->which_payload_variant != meshtastic_MeshPacket_decoded_tag || p->decoded.portnum != (meshtastic_PortNum)kroute::PORT)
        return false;
    if (kroute::peekType(p->decoded.payload.bytes, p->decoded.payload.size) != kroute::TYPE_ROUTED)
        return false;
    return kroute::decodeRouted(p->decoded.payload.bytes, p->decoded.payload.size, r) == kroute::Error::OK;
}

KRouteModule::KRouteModule() : SinglePortModule("kroute", (meshtastic_PortNum)kroute::PORT) {}

meshtastic_MeshPacket *krouteAllocRouteFail(const meshtastic_MeshPacket *pkt, uint32_t failedTo, uint8_t reason)
{
    meshtastic_MeshPacket *f = router->allocForSending();
    if (!f)
        return nullptr;
    f->to = getFrom(pkt);
    f->channel = pkt->channel;
    f->want_ack = false;
    f->decoded.portnum = (meshtastic_PortNum)kroute::PORT;
    kroute::RouteFail rf;
    rf.packetId = pkt->id;
    rf.failedFrom = nodeDB->getNodeNum();
    rf.failedTo = failedTo;
    rf.reason = reason;
    size_t len = 0;
    kroute::encodeRouteFail(rf, f->decoded.payload.bytes, sizeof(f->decoded.payload.bytes), &len);
    f->decoded.payload.size = len;
    return f;
}

void KRouteModule::deliverInner(const meshtastic_MeshPacket &mp, const kroute::Routed &r)
{
    // v1: the inner message goes to the API clients only (koldnet applications such as koldagent are
    // API clients). Firmware modules do not see it; the outer packet was already ACKed and deduplicated.
    meshtastic_MeshPacket *inner = packetPool.allocCopy(mp);
    if (!inner)
        return;
    inner->decoded.portnum = (meshtastic_PortNum)r.innerPort;
    memmove(inner->decoded.payload.bytes, r.inner, r.innerLen);
    inner->decoded.payload.size = r.innerLen;
    inner->want_ack = false;
    service->handleFromRadio(inner);
    packetPool.release(inner);
}

void KRouteModule::sendReceipt(const meshtastic_MeshPacket &mp, const kroute::Routed &r, bool byRoute, uint8_t hops)
{
    meshtastic_MeshPacket *p = allocDataPacket();
    if (!p)
        return;
    p->to = getFrom(&mp);
    p->channel = mp.channel;
    p->want_ack = false;
    kroute::Receipt rc;
    rc.packetId = mp.id;
    rc.byRoute = byRoute ? 1 : 0;
    rc.hops = hops;
    size_t len = 0;
    kroute::encodeReceipt(rc, p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes), &len);
    p->decoded.payload.size = len;
    service->sendToMesh(p);
}

ProcessMessage KRouteModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (!isToUs(&mp))
        return ProcessMessage::CONTINUE;
    uint8_t type = kroute::peekType(mp.decoded.payload.bytes, mp.decoded.payload.size);

#if KOLDNET_TEST_LINKS
    if (type == kroute::TYPE_TEST_LINKS && (mp.from == 0 || isFromUs(&mp))) {
        kroute::Error e = krouteTestLinks.load(mp.decoded.payload.bytes + 3, mp.decoded.payload.size - 3);
        LOG_WARN("koldnet TEST_LINKS: %s, dropping %u relay byte(s)", kroute::errorName(e), krouteTestLinks.count);
        return ProcessMessage::STOP;
    }
#endif

    if (type != kroute::TYPE_ROUTED)
        return ProcessMessage::CONTINUE; // ROUTE_FAIL and RECEIPT go to the API as they are

    kroute::Routed r;
    kroute::Error e = kroute::decodeRouted(mp.decoded.payload.bytes, mp.decoded.payload.size, &r);
    if (e != kroute::Error::OK) {
        LOG_WARN("koldnet KROUTE: dropped ROUTED 0x%08x from 0x%08x: %s", mp.id, mp.from, kroute::errorName(e));
        return ProcessMessage::CONTINUE;
    }
    uint8_t hops = (mp.hop_start >= mp.hop_limit) ? (uint8_t)(mp.hop_start - mp.hop_limit) : 0;
    bool injected = mp.hop_start == kroute::hopLimitFor(r.n, true);
    bool byRoute = kroute::deliveredByRoute(r, mp.relay_node, hops, injected);
    LOG_INFO("koldnet KROUTE: delivered 0x%08x from 0x%08x, %u relays, hops %u, last relay 0x%02x, by route %d, inner port %u",
             mp.id, mp.from, r.n, hops, mp.relay_node, byRoute, r.innerPort);
    deliverInner(mp, r);
    if (r.flags & kroute::FLAG_RECEIPT)
        sendReceipt(mp, r, byRoute, hops);
    return ProcessMessage::CONTINUE;
}

#endif
