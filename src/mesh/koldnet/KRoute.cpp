// koldnet forced routes, pure logic. SPEC-0002 #interfaces.
#include "KRoute.h"

#include <string.h>

namespace kroute
{

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

const char *errorName(Error e)
{
    switch (e) {
    case Error::OK:
        return "ok";
    case Error::TOO_SHORT:
        return "too short";
    case Error::BAD_MAGIC:
        return "bad magic";
    case Error::BAD_VERSION:
        return "bad version";
    case Error::BAD_TYPE:
        return "bad type";
    case Error::BAD_COUNT:
        return "relay count not 1 to 6";
    case Error::TOO_LONG:
        return "inner payload too long for this route";
    case Error::TOO_MANY_HOPS:
        return "route longer than hop_limit allows";
    case Error::REPEATED:
        return "relay listed twice";
    case Error::HAS_ENDPOINT:
        return "origin or destination listed as a relay";
    case Error::BAD_NODE:
        return "0 or broadcast in the route or as destination";
    case Error::UNKNOWN_FLAGS:
        return "unknown flags";
    case Error::NO_SPACE:
        return "output buffer too small";
    }
    return "?";
}

static Error header(const uint8_t *buf, size_t len, uint8_t type)
{
    if (len < 3)
        return Error::TOO_SHORT;
    if (buf[0] != MAGIC)
        return Error::BAD_MAGIC;
    if (buf[1] != VERSION)
        return Error::BAD_VERSION;
    if (buf[2] != type)
        return Error::BAD_TYPE;
    return Error::OK;
}

uint8_t peekType(const uint8_t *buf, size_t len)
{
    if (len < 3 || buf[0] != MAGIC || buf[1] != VERSION)
        return 0;
    return buf[2];
}

static Error checkRoute(const uint32_t *route, uint8_t n)
{
    if (n == 0 || n > MAX_RELAYS)
        return Error::BAD_COUNT;
    for (uint8_t i = 0; i < n; i++) {
        if (route[i] == 0 || route[i] == BROADCAST)
            return Error::BAD_NODE;
        for (uint8_t j = 0; j < i; j++)
            if (route[j] == route[i])
                return Error::REPEATED;
    }
    return Error::OK;
}

Error validate(uint32_t origin, uint32_t dest, const uint32_t *route, uint8_t n, size_t innerLen, bool injected)
{
    if (dest == 0 || dest == BROADCAST)
        return Error::BAD_NODE;
    Error e = checkRoute(route, n);
    if (e != Error::OK)
        return e;
    for (uint8_t i = 0; i < n; i++)
        if (route[i] == origin || route[i] == dest)
            return Error::HAS_ENDPOINT;
    if (hopLimitFor(n, injected) > KROUTE_HOP_MAX)
        return Error::TOO_MANY_HOPS;
    if (innerLen > maxInner(n))
        return Error::TOO_LONG;
    return Error::OK;
}

Error encodeRouted(const Routed &r, uint8_t *out, size_t cap, size_t *outLen)
{
    if (r.flags & ~FLAGS_KNOWN)
        return Error::UNKNOWN_FLAGS;
    Error e = checkRoute(r.route, r.n);
    if (e != Error::OK)
        return e;
    if (r.innerLen > maxInner(r.n))
        return Error::TOO_LONG;
    size_t need = ROUTED_OVERHEAD + 4u * r.n + r.innerLen;
    if (cap < need)
        return Error::NO_SPACE;
    out[0] = MAGIC;
    out[1] = VERSION;
    out[2] = TYPE_ROUTED;
    out[3] = r.flags;
    out[4] = r.n;
    size_t o = 5;
    for (uint8_t i = 0; i < r.n; i++, o += 4)
        put32(out + o, r.route[i]);
    out[o++] = (uint8_t)r.innerPort;
    out[o++] = (uint8_t)(r.innerPort >> 8);
    if (r.innerLen)
        memmove(out + o, r.inner, r.innerLen);
    *outLen = need;
    return Error::OK;
}

Error decodeRouted(const uint8_t *buf, size_t len, Routed *r)
{
    Error e = header(buf, len, TYPE_ROUTED);
    if (e != Error::OK)
        return e;
    if (len < 5)
        return Error::TOO_SHORT;
    uint8_t n = buf[4];
    if (n == 0 || n > MAX_RELAYS)
        return Error::BAD_COUNT;
    if (len < ROUTED_OVERHEAD + 4u * n)
        return Error::TOO_SHORT;
    r->flags = buf[3];
    r->n = n;
    size_t o = 5;
    for (uint8_t i = 0; i < n; i++, o += 4)
        r->route[i] = get32(buf + o);
    r->innerPort = (uint16_t)(buf[o] | (buf[o + 1] << 8));
    o += 2;
    r->inner = buf + o;
    r->innerLen = len - o;
    // Unknown flag bits from a later version are tolerated on receive; only the route is checked.
    return checkRoute(r->route, r->n);
}

Error encodeRouteFail(const RouteFail &f, uint8_t *out, size_t cap, size_t *outLen)
{
    if (cap < ROUTE_FAIL_LEN)
        return Error::NO_SPACE;
    out[0] = MAGIC;
    out[1] = VERSION;
    out[2] = TYPE_ROUTE_FAIL;
    put32(out + 3, f.packetId);
    put32(out + 7, f.failedFrom);
    put32(out + 11, f.failedTo);
    out[15] = f.reason;
    *outLen = ROUTE_FAIL_LEN;
    return Error::OK;
}

Error decodeRouteFail(const uint8_t *buf, size_t len, RouteFail *f)
{
    Error e = header(buf, len, TYPE_ROUTE_FAIL);
    if (e != Error::OK)
        return e;
    if (len < ROUTE_FAIL_LEN)
        return Error::TOO_SHORT;
    f->packetId = get32(buf + 3);
    f->failedFrom = get32(buf + 7);
    f->failedTo = get32(buf + 11);
    f->reason = buf[15];
    return Error::OK;
}

Error encodeReceipt(const Receipt &rc, uint8_t *out, size_t cap, size_t *outLen)
{
    if (cap < RECEIPT_LEN)
        return Error::NO_SPACE;
    out[0] = MAGIC;
    out[1] = VERSION;
    out[2] = TYPE_RECEIPT;
    put32(out + 3, rc.packetId);
    out[7] = rc.byRoute;
    out[8] = rc.hops;
    *outLen = RECEIPT_LEN;
    return Error::OK;
}

Error decodeReceipt(const uint8_t *buf, size_t len, Receipt *rc)
{
    Error e = header(buf, len, TYPE_RECEIPT);
    if (e != Error::OK)
        return e;
    if (len < RECEIPT_LEN)
        return Error::TOO_SHORT;
    rc->packetId = get32(buf + 3);
    rc->byRoute = buf[7];
    rc->hops = buf[8];
    return Error::OK;
}

int indexOf(const Routed &r, uint32_t self)
{
    for (uint8_t i = 0; i < r.n; i++)
        if (r.route[i] == self)
            return i;
    return -1;
}

HopDecision decideHop(const Routed &r, uint32_t self, uint32_t dest, uint8_t relayByte, bool injector)
{
    HopDecision d;
    int i = indexOf(r, self);
    if (i < 0) {
        if (!injector)
            return d; // STOCK
        d.action = HopDecision::FORWARD;
        d.index = -1;
        d.next = r.route[0];
        d.nextByte = lastByte(d.next);
        return d;
    }
    d.action = HopDecision::FORWARD;
    d.index = i;
    d.next = (i + 1 < r.n) ? r.route[i + 1] : dest;
    d.nextByte = lastByte(d.next);
    // A listed relay after the first must have heard it from the relay listed before it.
    // The first relay hears it from the origin or the injecting gateway, neither of which is listed.
    if (i > 0 && relayByte != lastByte(r.route[i - 1]))
        d.offRoute = true;
    return d;
}

bool isListedRelayByte(const Routed &r, uint8_t relayByte)
{
    for (uint8_t i = 0; i < r.n; i++)
        if (lastByte(r.route[i]) == relayByte)
            return true;
    return false;
}

bool deliveredByRoute(const Routed &r, uint8_t relayByte, uint8_t hopsTaken, bool injected)
{
    if (r.flags & FLAG_OFF_ROUTE)
        return false;
    if (relayByte != lastByte(r.route[r.n - 1]))
        return false;
    // hops counted from hop_start - hop_limit: every listed relay, plus the gateway when injected.
    return hopsTaken == (uint8_t)(r.n + (injected ? 1 : 0));
}

bool LinkFilter::drops(uint8_t relayByte) const
{
    for (uint8_t i = 0; i < count; i++)
        if (drop[i] == relayByte)
            return true;
    return false;
}

Error LinkFilter::load(const uint8_t *buf, size_t len)
{
    if (len < 1)
        return Error::TOO_SHORT;
    uint8_t c = buf[0];
    if (c > MAX_TEST_LINKS)
        return Error::BAD_COUNT;
    if (len < 1u + c)
        return Error::TOO_SHORT;
    count = c;
    memset(drop, 0, sizeof(drop));
    memcpy(drop, buf + 1, c);
    return Error::OK;
}

} // namespace kroute
