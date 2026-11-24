#pragma once
// koldnet forced routes (SPEC-0002): the destination side of the KROUTE wrapper on port 257,
// and the test-only link filter. The relay side is in NextHopRouter.
#include "SinglePortModule.h"
#include "mesh/koldnet/KRoute.h"

#if !MESHTASTIC_EXCLUDE_KROUTE

/** Decode a ROUTED wrapper from a decoded packet on port 257. False for anything else. */
bool krouteDecodeRouted(const meshtastic_MeshPacket *p, kroute::Routed *r);

class KRouteModule : public SinglePortModule
{
  public:
    KRouteModule();

  protected:
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

  private:
    void deliverInner(const meshtastic_MeshPacket &mp, const kroute::Routed &r);
    void sendReceipt(const meshtastic_MeshPacket &mp, const kroute::Routed &r, bool byRoute, uint8_t hops);
};

extern KRouteModule *krouteModule;

/** A ROUTE_FAIL from this node to the origin of pkt (SPEC-0002 #interfaces). The caller sends it. */
meshtastic_MeshPacket *krouteAllocRouteFail(const meshtastic_MeshPacket *pkt, uint32_t failedTo, uint8_t reason);

#if KOLDNET_TEST_LINKS
// Test builds only (SPEC-0002 D7): LoRa copies relayed by these bytes are dropped on receive.
extern kroute::LinkFilter krouteTestLinks;
#endif

#endif
