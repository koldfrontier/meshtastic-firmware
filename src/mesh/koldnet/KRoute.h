#pragma once
// koldnet forced routes (SPEC-0002 #interfaces): the KROUTE wrapper on port 257.
// Pure logic: no Router, NodeDB, radio or Arduino include, so it is tested on
// the host (test/test_kroute). The firmware glue is in NextHopRouter and
// KRouteModule.

#include <stddef.h>
#include <stdint.h>

namespace kroute
{

constexpr uint16_t PORT = 257;
constexpr uint8_t MAGIC = 0x4B;
constexpr uint8_t VERSION = 1;

constexpr uint8_t TYPE_ROUTED = 0x01;
constexpr uint8_t TYPE_ROUTE_FAIL = 0x02;
constexpr uint8_t TYPE_RECEIPT = 0x03;
constexpr uint8_t TYPE_TEST_LINKS = 0x10; // test builds only (KOLDNET_TEST_LINKS), local API only

constexpr uint8_t FLAG_STRICT = 0x01;    // no flood on the last retry; ROUTE_FAIL instead
constexpr uint8_t FLAG_OFF_ROUTE = 0x02; // set by a listed relay that got it from someone not listed before it
constexpr uint8_t FLAG_RECEIPT = 0x04;   // the destination sends a RECEIPT to the origin
constexpr uint8_t FLAGS_KNOWN = FLAG_STRICT | FLAG_OFF_ROUTE | FLAG_RECEIPT;

constexpr uint8_t MAX_RELAYS = 6;         // hop_limit is 3 bits (KROUTE_HOP_MAX 7): relays + 1 <= 7
constexpr uint8_t KROUTE_HOP_MAX = 7;
constexpr size_t DATA_PAYLOAD_MAX = 233;  // mesh.options *Data.payload max_size
constexpr size_t ROUTED_OVERHEAD = 7;     // magic, version, type, flags, n, inner_port(2); plus 4 per relay
constexpr size_t ROUTE_FAIL_LEN = 16;
constexpr size_t RECEIPT_LEN = 9;
constexpr uint8_t MAX_TEST_LINKS = 8;

constexpr uint32_t BROADCAST = 0xFFFFFFFF;

enum class Error : uint8_t {
    OK = 0,
    TOO_SHORT,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_TYPE,
    BAD_COUNT,      // n == 0 or n > MAX_RELAYS
    TOO_LONG,       // inner payload over the limit for this route length
    TOO_MANY_HOPS,  // relays (+1 when injected) + 1 > KROUTE_HOP_MAX
    REPEATED,       // a relay listed twice
    HAS_ENDPOINT,   // origin or destination listed as a relay
    BAD_NODE,       // 0 or broadcast listed, or a broadcast destination
    UNKNOWN_FLAGS,
    NO_SPACE,       // output buffer too small
};

const char *errorName(Error e);

struct Routed {
    uint8_t flags = 0;
    uint8_t n = 0;
    uint32_t route[MAX_RELAYS] = {0};
    uint16_t innerPort = 0;
    const uint8_t *inner = nullptr; // points into the decoded buffer, or the caller's data when encoding
    size_t innerLen = 0;
};

struct RouteFail {
    uint32_t packetId = 0;
    uint32_t failedFrom = 0;
    uint32_t failedTo = 0;
    uint8_t reason = 0;
};
constexpr uint8_t FAIL_NO_RELAY = 1;
constexpr uint8_t FAIL_NOT_IN_NODEDB = 2;
constexpr uint8_t FAIL_HOP_LIMIT = 3;

struct Receipt {
    uint32_t packetId = 0;
    uint8_t byRoute = 0; // 1 when every listed hop forwarded it as listed
    uint8_t hops = 0;    // hop_start - hop_limit seen at the destination
};

/** Last byte of a node number as the radio header carries it (0x00 becomes 0xFF; NodeDB.h:215). */
inline uint8_t lastByte(uint32_t node)
{
    return (node & 0xFF) ? (uint8_t)(node & 0xFF) : 0xFF;
}

/** The largest inner payload a route of n relays allows. */
inline size_t maxInner(uint8_t n)
{
    return DATA_PAYLOAD_MAX - ROUTED_OVERHEAD - 4u * n;
}

/** The type byte of a KROUTE payload, or 0 when it is not one (bad magic or version, too short). */
uint8_t peekType(const uint8_t *buf, size_t len);

/** Origin checks (SPEC-0002 #forced-route). injected: the packet enters through an MQTT gateway, one extra hop. */
Error validate(uint32_t origin, uint32_t dest, const uint32_t *route, uint8_t n, size_t innerLen, bool injected);

/** The hop_limit (= hop_start) the origin sets: relays + 1, plus 1 when injected through a gateway. */
inline uint8_t hopLimitFor(uint8_t n, bool injected)
{
    return (uint8_t)(n + 1 + (injected ? 1 : 0));
}

Error encodeRouted(const Routed &r, uint8_t *out, size_t cap, size_t *outLen);
Error decodeRouted(const uint8_t *buf, size_t len, Routed *r);

Error encodeRouteFail(const RouteFail &f, uint8_t *out, size_t cap, size_t *outLen);
Error decodeRouteFail(const uint8_t *buf, size_t len, RouteFail *f);

Error encodeReceipt(const Receipt &rc, uint8_t *out, size_t cap, size_t *outLen);
Error decodeReceipt(const uint8_t *buf, size_t len, Receipt *rc);

/** Position of self in the route by full node number (first occurrence), or -1. */
int indexOf(const Routed &r, uint32_t self);

/** What a node does with a ROUTED packet that is not addressed to it. */
struct HopDecision {
    enum Action : uint8_t {
        STOCK,   // not listed and not the injector: stock rules apply
        FORWARD, // forward with next_hop = nextByte
    } action = STOCK;
    int index = -1;       // our position in the route; -1 for the injector
    uint32_t next = 0;    // full node number of the next hop
    uint8_t nextByte = 0; // its last byte, for the header
    bool offRoute = false; // set FLAG_OFF_ROUTE before forwarding
};

/**
 * self: our node number; dest: the packet's destination; relayByte: relay_node of the copy we heard;
 * injector: we took it from MQTT (we are the first transmitter on LoRa).
 */
HopDecision decideHop(const Routed &r, uint32_t self, uint32_t dest, uint8_t relayByte, bool injector);

/** The next hop the origin puts in the header: the first relay. */
inline uint8_t firstHopByte(const Routed &r)
{
    return lastByte(r.route[0]);
}

/** On the last retry of a forced-route packet: flood (stock) or fail (strict). */
enum class LastRetry : uint8_t { FLOOD, FAIL };
inline LastRetry onLastRetry(const Routed &r)
{
    return (r.flags & FLAG_STRICT) ? LastRetry::FAIL : LastRetry::FLOOD;
}

/** True when relayByte is the last byte of a listed relay: a no-preference copy from it is that relay's fallback flood. */
bool isListedRelayByte(const Routed &r, uint8_t relayByte);

/** At the destination: did it come the forced way? */
bool deliveredByRoute(const Routed &r, uint8_t relayByte, uint8_t hopsTaken, bool injected);

/** Test-only link filter (KOLDNET_TEST_LINKS): drop a LoRa copy relayed by one of these bytes. */
struct LinkFilter {
    uint8_t count = 0;
    uint8_t drop[MAX_TEST_LINKS] = {0};
    bool drops(uint8_t relayByte) const;
    /** Payload after the type byte: count, then count bytes. count 0 clears. */
    Error load(const uint8_t *buf, size_t len);
};

} // namespace kroute
