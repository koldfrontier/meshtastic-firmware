// koldnet SPEC-0002: the KROUTE wrapper and the hop decisions, on the host.
// Edge-case numbers (E1..E20) refer to SPEC-0002 #edge-case-table.
#include "TestUtil.h"
#include "configuration.h" // Arduino.h: setup() and loop() with C linkage
#include "mesh/koldnet/KRoute.h"
#include <initializer_list>
#include <string.h>
#include <unity.h>

using namespace kroute;

#define ASSERT_ERR(exp, act) TEST_ASSERT_EQUAL_INT((int)(exp), (int)(act))

// Bench node numbers (inventory/nodes.md).
static const uint32_t A = 0x8fcd512c, B = 0x6ea15ca0, C = 0x1c15d508, D = 0x1b9dc120, E = 0x1b9dcb54, F = 0x1c15dbfc;
static const uint32_t SVC = 0x4B6F6C64; // SPEC-0001 service node

void setUp(void) {}
void tearDown(void) {}

static Routed routed(std::initializer_list<uint32_t> hops, uint8_t flags = 0, const char *inner = "hi")
{
    Routed r;
    r.flags = flags;
    for (uint32_t h : hops)
        r.route[r.n++] = h;
    r.innerPort = 256;
    r.inner = (const uint8_t *)inner;
    r.innerLen = strlen(inner);
    return r;
}

static void test_round_trip_keeps_route_flags_and_inner()
{
    Routed r = routed({F, A}, FLAG_STRICT | FLAG_RECEIPT, "classifier start");
    uint8_t buf[DATA_PAYLOAD_MAX];
    size_t len = 0;
    ASSERT_ERR(Error::OK, encodeRouted(r, buf, sizeof(buf), &len));
    TEST_ASSERT_EQUAL(ROUTED_OVERHEAD + 8 + 16, len);
    // The vector shared with koldnet tests/test_kroute.py.
    const uint8_t vector[] = {0x4b, 0x01, 0x01, 0x05, 0x02, 0xfc, 0xdb, 0x15, 0x1c, 0x2c, 0x51, 0xcd, 0x8f, 0x00, 0x01,
                              'c',  'l',  'a',  's',  's',  'i',  'f',  'i',  'e',  'r',  ' ',  's',  't',  'a',  'r', 't'};
    TEST_ASSERT_EQUAL(sizeof(vector), len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(vector, buf, sizeof(vector));
    TEST_ASSERT_EQUAL_HEX8(MAGIC, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(TYPE_ROUTED, peekType(buf, len));
    // little-endian node numbers
    TEST_ASSERT_EQUAL_HEX8(0xfc, buf[5]);
    TEST_ASSERT_EQUAL_HEX8(0x1c, buf[8]);
    Routed d;
    ASSERT_ERR(Error::OK, decodeRouted(buf, len, &d));
    TEST_ASSERT_EQUAL(2, d.n);
    TEST_ASSERT_EQUAL_HEX32(F, d.route[0]);
    TEST_ASSERT_EQUAL_HEX32(A, d.route[1]);
    TEST_ASSERT_EQUAL(FLAG_STRICT | FLAG_RECEIPT, d.flags);
    TEST_ASSERT_EQUAL(256, d.innerPort);
    TEST_ASSERT_EQUAL(16, d.innerLen);
    TEST_ASSERT_EQUAL_MEMORY("classifier start", d.inner, 16);
}

// E3: loops and endpoints in the route
static void test_repeated_relay_or_endpoint_is_refused()
{
    uint32_t loop[] = {F, A, F};
    ASSERT_ERR(Error::REPEATED, validate(C, D, loop, 3, 2, false));
    uint32_t hasOrigin[] = {F, C};
    ASSERT_ERR(Error::HAS_ENDPOINT, validate(C, D, hasOrigin, 2, 2, false));
    uint32_t hasDest[] = {D};
    ASSERT_ERR(Error::HAS_ENDPOINT, validate(C, D, hasDest, 1, 2, false));
    uint32_t bcast[] = {BROADCAST};
    ASSERT_ERR(Error::BAD_NODE, validate(C, D, bcast, 1, 2, false));
    uint32_t ok[] = {F};
    ASSERT_ERR(Error::BAD_NODE, validate(C, BROADCAST, ok, 1, 2, false));
}

// E4: route length versus hop_limit (D3: no bypass)
static void test_route_length_is_bounded_by_hop_limit()
{
    uint32_t six[] = {A, B, E, F, 0x11, 0x22};
    ASSERT_ERR(Error::OK, validate(C, D, six, 6, 1, false));
    TEST_ASSERT_EQUAL(7, hopLimitFor(6, false));
    // Injected through the MQTT gateway: one extra hop, so six relays no longer fit.
    ASSERT_ERR(Error::TOO_MANY_HOPS, validate(SVC, D, six, 6, 1, true));
    ASSERT_ERR(Error::OK, validate(SVC, D, six, 5, 1, true));
    uint32_t seven[] = {A, B, E, F, 0x11, 0x22, 0x33};
    ASSERT_ERR(Error::BAD_COUNT, validate(C, D, seven, 7, 1, false));
    ASSERT_ERR(Error::BAD_COUNT, validate(C, D, seven, 0, 1, false));
}

// E5: 233-byte payload versus route length
static void test_inner_payload_limit_depends_on_route_length()
{
    TEST_ASSERT_EQUAL(222, maxInner(1));
    TEST_ASSERT_EQUAL(202, maxInner(6));
    uint32_t one[] = {F};
    ASSERT_ERR(Error::OK, validate(C, D, one, 1, 222, false));
    ASSERT_ERR(Error::TOO_LONG, validate(C, D, one, 1, 223, false));
    static uint8_t big[300];
    Routed r = routed({F});
    r.inner = big;
    r.innerLen = 223;
    uint8_t buf[300];
    size_t len;
    ASSERT_ERR(Error::TOO_LONG, encodeRouted(r, buf, sizeof(buf), &len));
    r.innerLen = 222;
    ASSERT_ERR(Error::OK, encodeRouted(r, buf, sizeof(buf), &len));
    TEST_ASSERT_EQUAL(DATA_PAYLOAD_MAX, len);
}

// E18: version or magic mismatch
static void test_wrong_magic_version_or_truncation_is_rejected()
{
    Routed r = routed({F});
    uint8_t buf[64];
    size_t len;
    encodeRouted(r, buf, sizeof(buf), &len);
    Routed d;
    buf[1] = 2;
    ASSERT_ERR(Error::BAD_VERSION, decodeRouted(buf, len, &d));
    TEST_ASSERT_EQUAL(0, peekType(buf, len));
    buf[1] = VERSION;
    buf[0] = 0x4C;
    ASSERT_ERR(Error::BAD_MAGIC, decodeRouted(buf, len, &d));
    buf[0] = MAGIC;
    ASSERT_ERR(Error::TOO_SHORT, decodeRouted(buf, 8, &d));
    buf[4] = 7;
    ASSERT_ERR(Error::BAD_COUNT, decodeRouted(buf, len, &d));
}

static void test_unknown_flags_refused_on_encode_tolerated_on_decode()
{
    Routed r = routed({F}, 0x80);
    uint8_t buf[64];
    size_t len;
    ASSERT_ERR(Error::UNKNOWN_FLAGS, encodeRouted(r, buf, sizeof(buf), &len));
    r.flags = 0;
    encodeRouted(r, buf, sizeof(buf), &len);
    buf[3] = 0x80;
    Routed d;
    ASSERT_ERR(Error::OK, decodeRouted(buf, len, &d));
}

// The relay decision: listed relays forward to the next listed, the last to the destination.
static void test_listed_relays_forward_to_the_next_listed_hop()
{
    Routed r = routed({F, E});
    HopDecision h = decideHop(r, F, D, lastByte(C), false);
    TEST_ASSERT_EQUAL_INT(HopDecision::FORWARD, h.action);
    TEST_ASSERT_EQUAL(0, h.index);
    TEST_ASSERT_EQUAL_HEX32(E, h.next);
    TEST_ASSERT_EQUAL_HEX8(0x54, h.nextByte);
    TEST_ASSERT_FALSE(h.offRoute);
    h = decideHop(r, E, D, lastByte(F), false);
    TEST_ASSERT_EQUAL(1, h.index);
    TEST_ASSERT_EQUAL_HEX32(D, h.next);
    TEST_ASSERT_FALSE(h.offRoute);
}

// E6 / E16: a node not listed applies stock rules (it relays only if it is the header next hop).
static void test_unlisted_node_is_stock_even_with_a_colliding_last_byte()
{
    Routed r = routed({F});
    uint32_t sameByteAsF = 0x000000fc;
    TEST_ASSERT_EQUAL_INT(HopDecision::STOCK, decideHop(r, sameByteAsF, D, lastByte(C), false).action);
    TEST_ASSERT_EQUAL_INT(HopDecision::STOCK, decideHop(r, A, D, lastByte(C), false).action);
}

// E9: the MQTT gateway is the first transmitter; it sends to route[0].
static void test_injecting_gateway_forwards_to_the_first_relay()
{
    Routed r = routed({F, C});
    HopDecision h = decideHop(r, D, E, 0, true);
    TEST_ASSERT_EQUAL_INT(HopDecision::FORWARD, h.action);
    TEST_ASSERT_EQUAL(-1, h.index);
    TEST_ASSERT_EQUAL_HEX32(F, h.next);
}

// E1: a stock hop or a fallback flood in the middle: the next listed relay notices.
static void test_copy_from_an_unlisted_relay_is_marked_off_route()
{
    Routed r = routed({F, E});
    HopDecision h = decideHop(r, E, D, lastByte(A), false); // A (stock) relayed it, not F
    TEST_ASSERT_EQUAL_INT(HopDecision::FORWARD, h.action);
    TEST_ASSERT_TRUE(h.offRoute);
}

static void test_delivered_by_route_needs_the_last_relay_the_hop_count_and_no_off_route_flag()
{
    Routed r = routed({F, E});
    TEST_ASSERT_TRUE(deliveredByRoute(r, lastByte(E), 2, false));
    TEST_ASSERT_FALSE(deliveredByRoute(r, lastByte(F), 2, false)); // last relay was not E
    TEST_ASSERT_FALSE(deliveredByRoute(r, lastByte(E), 3, false)); // an extra hop
    TEST_ASSERT_TRUE(deliveredByRoute(r, lastByte(E), 3, true));   // the gateway hop when injected
    r.flags |= FLAG_OFF_ROUTE;
    TEST_ASSERT_FALSE(deliveredByRoute(r, lastByte(E), 2, false));
}

// E14: a no-preference copy from a listed relay is that relay's fallback flood.
static void test_listed_relay_byte_identifies_a_fallback_flood_source()
{
    Routed r = routed({F, E});
    TEST_ASSERT_TRUE(isListedRelayByte(r, 0xfc));
    TEST_ASSERT_TRUE(isListedRelayByte(r, 0x54));
    TEST_ASSERT_FALSE(isListedRelayByte(r, lastByte(A)));
}

// E2 / E14 / E15: last retry floods unless strict (D2).
static void test_last_retry_floods_unless_strict()
{
    TEST_ASSERT_EQUAL((int)LastRetry::FLOOD, (int)onLastRetry(routed({F})));
    TEST_ASSERT_EQUAL((int)LastRetry::FAIL, (int)onLastRetry(routed({F}, FLAG_STRICT)));
}

static void test_route_fail_and_receipt_round_trip()
{
    uint8_t buf[32];
    size_t len;
    RouteFail f{0x1234abcd, F, E, FAIL_NO_RELAY};
    ASSERT_ERR(Error::OK, encodeRouteFail(f, buf, sizeof(buf), &len));
    TEST_ASSERT_EQUAL(ROUTE_FAIL_LEN, len);
    TEST_ASSERT_EQUAL_HEX8(TYPE_ROUTE_FAIL, peekType(buf, len));
    RouteFail g;
    ASSERT_ERR(Error::OK, decodeRouteFail(buf, len, &g));
    TEST_ASSERT_EQUAL_HEX32(0x1234abcd, g.packetId);
    TEST_ASSERT_EQUAL_HEX32(F, g.failedFrom);
    TEST_ASSERT_EQUAL_HEX32(E, g.failedTo);
    TEST_ASSERT_EQUAL(FAIL_NO_RELAY, g.reason);
    Receipt rc{0x55, 1, 2};
    ASSERT_ERR(Error::OK, encodeReceipt(rc, buf, sizeof(buf), &len));
    Receipt rd;
    ASSERT_ERR(Error::OK, decodeReceipt(buf, len, &rd));
    TEST_ASSERT_EQUAL(0x55, rd.packetId);
    TEST_ASSERT_EQUAL(1, rd.byRoute);
    TEST_ASSERT_EQUAL(2, rd.hops);
    ASSERT_ERR(Error::BAD_TYPE, decodeRouteFail(buf, len, &g));
}

static void test_last_byte_zero_maps_to_ff()
{
    TEST_ASSERT_EQUAL_HEX8(0xFF, lastByte(0x12345600));
    TEST_ASSERT_EQUAL_HEX8(0x2c, lastByte(A));
}

// D7 test filter.
static void test_link_filter_loads_and_drops_listed_relays()
{
    LinkFilter lf;
    const uint8_t cfg[] = {2, 0x08, 0xfc};
    ASSERT_ERR(Error::OK, lf.load(cfg, sizeof(cfg)));
    TEST_ASSERT_TRUE(lf.drops(0x08));
    TEST_ASSERT_TRUE(lf.drops(0xfc));
    TEST_ASSERT_FALSE(lf.drops(0x20));
    const uint8_t clear[] = {0};
    ASSERT_ERR(Error::OK, lf.load(clear, 1));
    TEST_ASSERT_FALSE(lf.drops(0x08));
    const uint8_t tooMany[] = {9};
    ASSERT_ERR(Error::BAD_COUNT, lf.load(tooMany, 1));
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_round_trip_keeps_route_flags_and_inner);
    RUN_TEST(test_repeated_relay_or_endpoint_is_refused);
    RUN_TEST(test_route_length_is_bounded_by_hop_limit);
    RUN_TEST(test_inner_payload_limit_depends_on_route_length);
    RUN_TEST(test_wrong_magic_version_or_truncation_is_rejected);
    RUN_TEST(test_unknown_flags_refused_on_encode_tolerated_on_decode);
    RUN_TEST(test_listed_relays_forward_to_the_next_listed_hop);
    RUN_TEST(test_unlisted_node_is_stock_even_with_a_colliding_last_byte);
    RUN_TEST(test_injecting_gateway_forwards_to_the_first_relay);
    RUN_TEST(test_copy_from_an_unlisted_relay_is_marked_off_route);
    RUN_TEST(test_delivered_by_route_needs_the_last_relay_the_hop_count_and_no_off_route_flag);
    RUN_TEST(test_listed_relay_byte_identifies_a_fallback_flood_source);
    RUN_TEST(test_last_retry_floods_unless_strict);
    RUN_TEST(test_route_fail_and_receipt_round_trip);
    RUN_TEST(test_last_byte_zero_maps_to_ff);
    RUN_TEST(test_link_filter_loads_and_drops_listed_relays);
    exit(UNITY_END());
}

void loop() {}
