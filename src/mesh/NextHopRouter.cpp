#include "NextHopRouter.h"
#include "MeshTypes.h"
#include "meshUtils.h"
#if !MESHTASTIC_EXCLUDE_TRACEROUTE
#include "modules/TraceRouteModule.h"
#endif
#include "NodeDB.h"
#if !MESHTASTIC_EXCLUDE_KROUTE
#include "MeshService.h"
#include "modules/KRouteModule.h"
#include <vector>
#endif

NextHopRouter::NextHopRouter() {}

PendingPacket::PendingPacket(meshtastic_MeshPacket *p, uint8_t numRetransmissions)
{
    packet = p;
    this->numRetransmissions = numRetransmissions - 1; // We subtract one, because we assume the user just did the first send
}

/**
 * Send a packet
 */
ErrorCode NextHopRouter::send(meshtastic_MeshPacket *p)
{
    // Add any messages _we_ send to the seen message list (so we will ignore all retransmissions we see)
    p->relay_node = nodeDB->getLastByteOfNodeNum(getNodeNum()); // First set the relayer to us
    wasSeenRecently(p);                                         // FIXME, move this to a sniffSent method

    p->next_hop = getNextHop(p->to, p->relay_node).value_or(NO_NEXT_HOP_PREFERENCE); // set the next hop
#if !MESHTASTIC_EXCLUDE_KROUTE
    // koldnet forced route (SPEC-0002): the route in the payload decides the next hop, not the NodeDB.
    if (auto kr = krouteNextHop(p))
        p->next_hop = *kr;
#endif
    LOG_DEBUG("Setting next hop for packet with dest %x to %x", p->to, p->next_hop);

    // If it's from us, ReliableRouter already handles retransmissions if want_ack is set. If a next hop is set and hop limit is
    // not 0 or want_ack is set, start retransmissions
    if ((!isFromUs(p) || !p->want_ack) && p->next_hop != NO_NEXT_HOP_PREFERENCE && (p->hop_limit > 0 || p->want_ack))
        startRetransmission(packetPool.allocCopy(*p)); // start retransmission for relayed packet

    return Router::send(p);
}

bool NextHopRouter::shouldFilterReceived(const meshtastic_MeshPacket *p)
{
    bool wasFallback = false;
    bool weWereNextHop = false;
    bool wasUpgraded = false;
    bool seenRecently = wasSeenRecently(p, true, &wasFallback, &weWereNextHop,
                                        &wasUpgraded); // Updates history; returns false when an upgrade is detected

    // Handle hop_limit upgrade scenario for rebroadcasters
    if (wasUpgraded && perhapsHandleUpgradedPacket(p)) {
        return true; // we handled it, so stop processing
    }

    if (seenRecently) {
        printPacket("Ignore dupe incoming msg", p);

        if (p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA) {
            rxDupe++;
            stopRetransmission(p->from, p->id);
        }

        // If it was a fallback to flooding, try to relay again
        if (wasFallback) {
            LOG_INFO("Fallback to flooding from relay_node=0x%x", p->relay_node);
            // Check if it's still in the Tx queue, if not, we have to relay it again
            if (!findInTxQueue(p->from, p->id)) {
                reprocessPacket(p);
                perhapsRebroadcast(p);
            }
        } else {
            bool isRepeated = getHopsAway(*p) == 0;
            // If repeated and not in Tx queue anymore, try relaying again, or if we are the destination, send the ACK again
            if (isRepeated) {
                if (!findInTxQueue(p->from, p->id)) {
                    reprocessPacket(p);
                    if (!perhapsRebroadcast(p) && isToUs(p) && p->want_ack) {
                        sendAckNak(meshtastic_Routing_Error_NONE, getFrom(p), p->id, p->channel, 0);
                    }
                }
            } else if (!weWereNextHop) {
                perhapsCancelDupe(p); // If it's a dupe, cancel relay if we were not explicitly asked to relay
            }
        }
        return true;
    }

    return Router::shouldFilterReceived(p);
}

void NextHopRouter::sniffReceived(const meshtastic_MeshPacket *p, const meshtastic_Routing *c)
{
    NodeNum ourNodeNum = getNodeNum();
    uint8_t ourRelayID = nodeDB->getLastByteOfNodeNum(ourNodeNum);
    bool isAckorReply = (p->which_payload_variant == meshtastic_MeshPacket_decoded_tag) &&
                        (p->decoded.request_id != 0 || p->decoded.reply_id != 0);
    if (isAckorReply) {
        // Update next-hop for the original transmitter of this successful transmission to the relay node, but ONLY if "from"
        // is not 0 (means implicit ACK) and original packet was also relayed by this node, or we sent it directly to the
        // destination
        if (p->from != 0) {
            meshtastic_NodeInfoLite *origTx = nodeDB->getMeshNode(p->from);
            if (origTx) {
                // Either relayer of ACK was also a relayer of the packet, or we were the *only* relayer and the ACK came
                // directly from the destination
                bool wasAlreadyRelayer = wasRelayer(p->relay_node, p->decoded.request_id, p->to);
                bool weWereSoleRelayer = false;
                bool weWereRelayer = wasRelayer(ourRelayID, p->decoded.request_id, p->to, &weWereSoleRelayer);
                if ((weWereRelayer && wasAlreadyRelayer) || (getHopsAway(*p) == 0 && weWereSoleRelayer)) {
                    if (origTx->next_hop != p->relay_node) { // Not already set
                        LOG_INFO("Update next hop of 0x%x to 0x%x based on ACK/reply (was relayer %d we were sole %d)", p->from,
                                 p->relay_node, wasAlreadyRelayer, weWereSoleRelayer);
                        origTx->next_hop = p->relay_node;
                    }
                }
            }
        }
        if (!isToUs(p)) {
            Router::cancelSending(p->to, p->decoded.request_id); // cancel rebroadcast for this DM
            // stop retransmission for the original packet
            stopRetransmission(p->to, p->decoded.request_id); // for original packet, from = to and id = request_id
        }
    }

    perhapsRebroadcast(p);

    // handle the packet as normal
    Router::sniffReceived(p, c);
}

/* Check if we should be rebroadcasting this packet if so, do so. */
bool NextHopRouter::perhapsRebroadcast(const meshtastic_MeshPacket *p)
{
#if !MESHTASTIC_EXCLUDE_KROUTE
    int kr = perhapsRebroadcastKRoute(p);
    if (kr >= 0)
        return kr == 1;
#endif
    if (!isToUs(p) && !isFromUs(p) && p->hop_limit > 0) {
        if (p->id != 0) {
            if (isRebroadcaster()) {
                if (p->next_hop == NO_NEXT_HOP_PREFERENCE || p->next_hop == nodeDB->getLastByteOfNodeNum(getNodeNum())) {
                    meshtastic_MeshPacket *tosend = packetPool.allocCopy(*p); // keep a copy because we will be sending it
                    LOG_INFO("Rebroadcast received message coming from %x", p->relay_node);

                    // Use shared logic to determine if hop_limit should be decremented
                    if (shouldDecrementHopLimit(p)) {
                        tosend->hop_limit--; // bump down the hop count
                    } else {
                        LOG_INFO("favorite-ROUTER/CLIENT_BASE-to-ROUTER/CLIENT_BASE rebroadcast: preserving hop_limit");
                    }
#if USERPREFS_EVENT_MODE
                    if (tosend->hop_limit > 2) {
                        // if we are "correcting" the hop_limit, "correct" the hop_start by the same amount to preserve hops away.
                        tosend->hop_start -= (tosend->hop_limit - 2);
                        tosend->hop_limit = 2;
                    }
#endif

                    if (p->next_hop == NO_NEXT_HOP_PREFERENCE) {
                        FloodingRouter::send(tosend);
                    } else {
                        NextHopRouter::send(tosend);
                    }

                    return true;
                }
            } else {
                LOG_DEBUG("No rebroadcast: Role = CLIENT_MUTE or Rebroadcast Mode = NONE");
            }
        } else {
            LOG_DEBUG("Ignore 0 id broadcast");
        }
    }

    return false;
}

/**
 * Get the next hop for a destination, given the relay node
 * @return the node number of the next hop, 0 if no preference (fallback to FloodingRouter)
 */
std::optional<uint8_t> NextHopRouter::getNextHop(NodeNum to, uint8_t relay_node)
{
    if (isBroadcast(to))
        return std::nullopt;

    meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(to);
    if (node && node->next_hop) {
        // We are careful not to return the relay node as the next hop
        if (node->next_hop != relay_node) {
            // LOG_DEBUG("Next hop for 0x%x is 0x%x", to, node->next_hop);
            return node->next_hop;
        } else
            LOG_WARN("Next hop for 0x%x is 0x%x, same as relayer; set no pref", to, node->next_hop);
    }
    return std::nullopt;
}

PendingPacket *NextHopRouter::findPendingPacket(GlobalPacketId key)
{
    auto old = pending.find(key); // If we have an old record, someone messed up because id got reused
    if (old != pending.end()) {
        return &old->second;
    } else
        return NULL;
}

/**
 * Stop any retransmissions we are doing of the specified node/packet ID pair
 */
bool NextHopRouter::stopRetransmission(NodeNum from, PacketId id)
{
    auto key = GlobalPacketId(from, id);
    return stopRetransmission(key);
}

bool NextHopRouter::roleAllowsCancelingFromTxQueue(const meshtastic_MeshPacket *p)
{
    // Return true if we're allowed to cancel a packet in the txQueue (so we may never transmit it even once)

    // Return false for roles like ROUTER, ROUTER_LATE which should always transmit the packet at least once.

    return roleAllowsCancelingDupe(p); // same logic as FloodingRouter::roleAllowsCancelingDupe
}

bool NextHopRouter::stopRetransmission(GlobalPacketId key)
{
    auto old = findPendingPacket(key);
    if (old) {
        auto p = old->packet;
        /* Only when we already transmitted a packet via LoRa, we will cancel the packet in the Tx queue
          to avoid canceling a transmission if it was ACKed super fast via MQTT */
        if (old->numRetransmissions < NUM_RELIABLE_RETX - 1) {
            // We only cancel it if we are the original sender or if we're not a router(_late)
            if (isFromUs(p) || roleAllowsCancelingFromTxQueue(p)) {
                // remove the 'original' (identified by originator and packet->id) from the txqueue and free it
                cancelSending(getFrom(p), p->id);
            }
        }

        // Regardless of whether or not we canceled this packet from the txQueue, remove it from our pending list so it
        // doesn't get scheduled again. (This is the core of stopRetransmission.)
        auto numErased = pending.erase(key);
        assert(numErased == 1);

        // When we remove an entry from pending, always be sure to release the copy of the packet that was allocated in the
        // call to startRetransmission.
        packetPool.release(p);

        return true;
    } else
        return false;
}

/**
 * Add p to the list of packets to retransmit occasionally.  We will free it once we stop retransmitting.
 */
PendingPacket *NextHopRouter::startRetransmission(meshtastic_MeshPacket *p, uint8_t numReTx)
{
    auto id = GlobalPacketId(p);
    auto rec = PendingPacket(p, numReTx);

    stopRetransmission(getFrom(p), p->id);

    setNextTx(&rec);
    pending[id] = rec;

    return &pending[id];
}

/**
 * Do any retransmissions that are scheduled (FIXME - for the time being called from loop)
 */
int32_t NextHopRouter::doRetransmissions()
{
    uint32_t now = millis();
    int32_t d = INT32_MAX;

    // FIXME, we should use a better datastructure rather than walking through this map.
    // for(auto el: pending) {
    for (auto it = pending.begin(), nextIt = it; it != pending.end(); it = nextIt) {
        ++nextIt; // we use this odd pattern because we might be deleting it...
        auto &p = it->second;

        bool stillValid = true; // assume we'll keep this record around

        // FIXME, handle 51 day rolloever here!!!
        if (p.nextTxMsec <= now) {
            if (p.numRetransmissions == 0) {
                if (isFromUs(p.packet)) {
                    LOG_DEBUG("Reliable send failed, returning a nak for fr=0x%x,to=0x%x,id=0x%x", p.packet->from, p.packet->to,
                              p.packet->id);
                    sendAckNak(meshtastic_Routing_Error_MAX_RETRANSMIT, getFrom(p.packet), p.packet->id, p.packet->channel);
                }
#if !MESHTASTIC_EXCLUDE_KROUTE
                kroute::Routed kr;
                if (!isFromUs(p.packet) && !isBroadcast(p.packet->to) && krouteDecodeRouted(p.packet, &kr) &&
                    (kr.flags & kroute::FLAG_STRICT)) {
                    // A strict forced route died at our next hop: tell the origin which link (SPEC-0002 #interfaces).
                    auto h = kroute::decideHop(kr, getNodeNum(), p.packet->to, 0,
                                               p.packet->transport_mechanism ==
                                                   meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT);
                    uint8_t reason = nodeDB->getMeshNode(h.next) ? kroute::FAIL_NO_RELAY : kroute::FAIL_NOT_IN_NODEDB;
                    LOG_INFO("koldnet KROUTE: strict route 0x%08x failed at 0x%08x -> 0x%08x, ROUTE_FAIL to 0x%08x", p.packet->id,
                             getNodeNum(), h.next, getFrom(p.packet));
                    if (auto f = krouteAllocRouteFail(p.packet, h.next, reason))
                        krouteDeferred.push_back(f); // sent after the loop: sending may change `pending`
                }
#endif
                // Note: we don't stop retransmission here, instead the Nak packet gets processed in sniffReceived
                stopRetransmission(it->first);
                stillValid = false; // just deleted it
            } else {
                LOG_DEBUG("Sending retransmission fr=0x%x,to=0x%x,id=0x%x, tries left=%d", p.packet->from, p.packet->to,
                          p.packet->id, p.numRetransmissions);

                if (!isBroadcast(p.packet->to)) {
#if !MESHTASTIC_EXCLUDE_KROUTE
                    kroute::Routed kr;
                    bool strictRoute =
                        p.numRetransmissions == 1 && krouteDecodeRouted(p.packet, &kr) && (kr.flags & kroute::FLAG_STRICT);
                    if (strictRoute) {
                        // SPEC-0002 D2, strict: the last retry stays directed (no flood) and the learned next hop is
                        // kept. If that fails too, the relay sends ROUTE_FAIL (numRetransmissions == 0 above).
                        LOG_INFO("koldnet KROUTE: strict route 0x%08x, last retry stays on next hop 0x%02x", p.packet->id,
                                 p.packet->next_hop);
                        // FloodingRouter::send keeps the header next hop; NextHopRouter::send would restart this record.
                        FloodingRouter::send(packetPool.allocCopy(*p.packet));
                    } else
#endif
                    if (p.numRetransmissions == 1) {
                        // Last retransmission, reset next_hop (fallback to FloodingRouter)
                        p.packet->next_hop = NO_NEXT_HOP_PREFERENCE;
                        // Also reset it in the nodeDB
                        meshtastic_NodeInfoLite *sentTo = nodeDB->getMeshNode(p.packet->to);
                        if (sentTo) {
                            LOG_INFO("Resetting next hop for packet with dest 0x%x\n", p.packet->to);
                            sentTo->next_hop = NO_NEXT_HOP_PREFERENCE;
                        }
                        FloodingRouter::send(packetPool.allocCopy(*p.packet));
                    } else {
                        NextHopRouter::send(packetPool.allocCopy(*p.packet));
                    }
                } else {
                    // Note: we call the superclass version because we don't want to have our version of send() add a new
                    // retransmission record
                    FloodingRouter::send(packetPool.allocCopy(*p.packet));
                }

                // Queue again
                --p.numRetransmissions;
                setNextTx(&p);
            }
        }

        if (stillValid) {
            // Update our desired sleep delay
            int32_t t = p.nextTxMsec - now;

            d = min(t, d);
        }
    }

#if !MESHTASTIC_EXCLUDE_KROUTE
    for (auto f : krouteDeferred)
        service->sendToMesh(f);
    krouteDeferred.clear();
#endif

    return d;
}

void NextHopRouter::setNextTx(PendingPacket *pending)
{
    assert(iface);
    auto d = iface->getRetransmissionMsec(pending->packet);
    pending->nextTxMsec = millis() + d;
    LOG_DEBUG("Setting next retransmission in %u msecs: ", d);
    printPacket("", pending->packet);
    setReceivedMessage(); // Run ASAP, so we can figure out our correct sleep time
}

#if !MESHTASTIC_EXCLUDE_KROUTE
/**
 * koldnet forced route: the header next hop for a ROUTED packet we are about to send, or nullopt to leave the
 * stock choice. The origin sends to route[0]; a listed relay to the next listed hop or the destination; the gateway
 * that took the packet from MQTT to route[0]. SPEC-0002 #interfaces.
 */
std::optional<uint8_t> NextHopRouter::krouteNextHop(const meshtastic_MeshPacket *p)
{
    kroute::Routed r;
    if (isBroadcast(p->to) || !krouteDecodeRouted(p, &r))
        return std::nullopt;
    if (isFromUs(p))
        return kroute::firstHopByte(r);
    bool injector = p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    auto h = kroute::decideHop(r, getNodeNum(), p->to, 0, injector);
    if (h.action == kroute::HopDecision::FORWARD)
        return h.nextByte;
    return std::nullopt;
}

/**
 * koldnet forced route relay. Returns -1 when stock rules apply (not a ROUTED packet, or we are neither listed nor
 * the injecting gateway), 1 when we relayed, 0 when we must not relay.
 */
int NextHopRouter::perhapsRebroadcastKRoute(const meshtastic_MeshPacket *p)
{
    if (isToUs(p) || isFromUs(p) || p->hop_limit == 0 || p->id == 0 || isBroadcast(p->to) || !isRebroadcaster())
        return -1;
    kroute::Routed r;
    if (!krouteDecodeRouted(p, &r))
        return -1;
    bool injector = p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    auto h = kroute::decideHop(r, getNodeNum(), p->to, p->relay_node, injector);
    if (h.action != kroute::HopDecision::FORWARD)
        return -1;
    uint8_t ours = nodeDB->getLastByteOfNodeNum(getNodeNum());
    if (!injector && p->next_hop != ours && p->next_hop != NO_NEXT_HOP_PREFERENCE) {
        // Listed, but the copy we heard is aimed at another hop (e.g. we are route[1] and heard the origin).
        LOG_DEBUG("koldnet KROUTE: 0x%08x is for next hop 0x%02x, not us; not relaying", p->id, p->next_hop);
        return 0;
    }
    meshtastic_MeshPacket *tosend = packetPool.allocCopy(*p);
    if (shouldDecrementHopLimit(p))
        tosend->hop_limit--;
    if (h.offRoute)
        tosend->decoded.payload.bytes[3] |= kroute::FLAG_OFF_ROUTE; // flags byte (SPEC-0002 #interfaces)
    LOG_INFO("koldnet KROUTE: relay 0x%08x (index %d) to next hop 0x%08x (0x%02x)%s", p->id, h.index, h.next, h.nextByte,
             h.offRoute ? ", off route" : "");
    NextHopRouter::send(tosend); // krouteNextHop sets the header next hop
    return 1;
}
#endif
