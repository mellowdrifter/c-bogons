/*
 * Copyright (C) 2026 Darren O'Connor <mellow.drifter@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bogons.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

const char *bogon_version(void) {
    return BOGONS_VERSION;
}

/* =========================================================================
 * Internal Structures & Constants
 * ========================================================================= */

struct v4_rule {
    uint32_t net;
    uint32_t mask;
    const char *reason;
};

struct v6_rule {
    uint8_t net[16];
    uint8_t mask_bits;
    const char *reason;
};

struct as_rule {
    uint32_t start;
    uint32_t end;
    const char *reason;
};

static inline uint32_t v4_calc_mask(uint8_t bits) {
    if (bits == 0) return 0;
    if (bits >= 32) return 0xFFFFFFFFU;
    return ~((1U << (32 - bits)) - 1U);
}

static const struct v4_rule V4_RULES[23] = {
    { 0x00000000U, 0xFF000000U, "RFC 1122 (This Host on This Network)" },
    { 0x0A000000U, 0xFF000000U, "RFC 1918 (Private-Use)" },
    { 0x64400000U, 0xFFC00000U, "RFC 6598 (Shared Address Space / CGNAT)" },
    { 0x7F000000U, 0xFF000000U, "RFC 1122 (Loopback)" },
    { 0xA9FE0000U, 0xFFFF0000U, "RFC 3927 (Link-Local)" },
    { 0xAC100000U, 0xFFF00000U, "RFC 1918 (Private-Use)" },
    { 0xC00000AAU, 0xFFFFFFFEU, "RFC 8880 (NAT64/DNS64 Discovery)" },
    { 0xC000000AU, 0xFFFFFFFFU, "RFC 8155 (TURN Anycast)" },
    { 0xC0000009U, 0xFFFFFFFFU, "RFC 7725 (PCP Anycast)" },
    { 0xC0000008U, 0xFFFFFFFFU, "RFC 7600 (IPv4 Dummy Address)" },
    { 0xC0000000U, 0xFFFFFFF8U, "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)" },
    { 0xC0000000U, 0xFFFFFF00U, "RFC 6890 (IETF Protocol Assignments)" },
    { 0xC0000200U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-1)" },
    { 0xC01FC400U, 0xFFFFFF00U, "RFC 7535 (AS112-v4)" },
    { 0xC034C100U, 0xFFFFFF00U, "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    { 0xC0586300U, 0xFFFFFF00U, "RFC 7526 (6to4 Relay Anycast - Deprecated)" },
    { 0xC0A80000U, 0xFFFF0000U, "RFC 1918 (Private-Use)" },
    { 0xC6120000U, 0xFFFE0000U, "RFC 2544 (Benchmarking)" },
    { 0xC6336400U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-2)" },
    { 0xCB007100U, 0xFFFFFF00U, "RFC 5737 (Documentation TEST-NET-3)" },
    { 0xE0000000U, 0xF0000000U, "RFC 1112 (Multicast)" },
    { 0xFFFFFFFFU, 0xFFFFFFFFU, "RFC 919 / RFC 8190 (Limited Broadcast)" },
    { 0xF0000000U, 0xF0000000U, "RFC 1112 (Reserved / Former Class E)" },
};

static const struct v6_rule V6_RULES[17] = {
    // 2001:db8::/32
    { { 0x20, 0x01, 0x0d, 0xb8 }, 32, "RFC 3849 (Documentation)" },
    // 2001::/32
    { { 0x20, 0x01, 0x00, 0x00 }, 32, "RFC 4380 (Teredo)" },
    // 2001:1::1/128
    { { 0x20, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 128, "RFC 7723 (PCP Anycast)" },
    // 2001:1::2/128
    { { 0x20, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }, 128, "RFC 8155 (TURN Anycast)" },
    // 2001:2::/48
    { { 0x20, 0x01, 0x00, 0x02 }, 48, "RFC 5180 / RFC 9006 (Benchmarking)" },
    // 2001:3::/32
    { { 0x20, 0x01, 0x00, 0x03 }, 32, "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    // 2001:4:112::/48
    { { 0x20, 0x01, 0x00, 0x04, 0x01, 0x12 }, 48, "RFC 7535 (AS112-v6)" },
    // 2001:10::/28
    { { 0x20, 0x01, 0x00, 0x10 }, 28, "RFC 4843 (Deprecated ORCHID)" },
    // 2001:20::/28
    { { 0x20, 0x01, 0x00, 0x20 }, 28, "RFC 7343 (ORCHIDv2)" },
    // 2001:30::/28
    { { 0x20, 0x01, 0x00, 0x30 }, 28, "RFC 9385 (Drone Remote ID)" },
    // 2001::/23
    { { 0x20, 0x01, 0x00, 0x00 }, 23, "RFC 2928 (IETF Protocol Assignments)" },
    // 2002::/16
    { { 0x20, 0x02 }, 16, "RFC 3056 / RFC 7526 (6to4 - Deprecated)" },
    // 2620:4f:8000::/48
    { { 0x26, 0x20, 0x00, 0x4f, 0x80, 0x00 }, 48, "RFC 7534 (Direct Delegation AS112)" },
    // 64:ff9b:1::/48
    { { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01 }, 48, "RFC 8215 (Local-Use IPv4/IPv6 Translation)" },
    // 64:ff9b::/96
    { { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 }, 96, "RFC 6052 (IPv4/IPv6 Translation)" },
    // 100::/64
    { { 0x01, 0x00, 0, 0, 0, 0, 0, 0 }, 64, "RFC 6666 (Discard-Only)" },
    // 3ffe::/16
    { { 0x3f, 0xfe }, 16, "RFC 3701 (6bone - Deprecated / Returned)" },
};

static const struct as_rule AS_RULES[9] = {
    { 0U, 0U, "RFC 6483 / RFC 7607 (Reserved ASN 0)" },
    { 23456U, 23456U, "RFC 6793 (AS_TRANS 4-Byte Transition)" },
    { 64496U, 64511U, "RFC 5398 (Documentation 16-bit)" },
    { 64512U, 65534U, "RFC 1930 / RFC 6996 (Private-Use 16-bit)" },
    { 65535U, 65535U, "RFC 7300 (Reserved 16-bit Last ASN)" },
    { 65536U, 65551U, "RFC 5398 (Documentation 32-bit)" },
    { 65552U, 131071U, "RFC 7249 / IANA (Reserved 32-bit)" },
    { 4200000000U, 4294967294U, "RFC 6996 (Private-Use 32-bit)" },
    { 4294967295U, 4294967295U, "RFC 7300 (Reserved 32-bit Last ASN)" },
};

/* =========================================================================
 * ASN Functions
 * ========================================================================= */

bool bogon_check_asn(uint32_t asn, const char **reason) {
    for (size_t i = 0; i < sizeof(AS_RULES)/sizeof(AS_RULES[0]); i++) {
        if (asn >= AS_RULES[i].start && asn <= AS_RULES[i].end) {
            if (reason) *reason = AS_RULES[i].reason;
            return false;
        }
    }
    if (reason) *reason = NULL;
    return true;
}

bool bogon_is_public_asn(uint32_t asn) {
    return bogon_check_asn(asn, NULL);
}

bool bogon_parse_asn(const char *str, uint32_t *out_asn) {
    if (!str || !out_asn) return false;

    // Skip leading whitespace
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return false;

    // Skip optional "AS" / "as" prefix
    if ((str[0] == 'A' || str[0] == 'a') && (str[1] == 'S' || str[1] == 's')) {
        str += 2;
    }
    if (*str == '\0') return false;

    const char *dot = strchr(str, '.');
    if (dot) {
        // asdot notation: high.low
        char high_buf[16] = {0};
        char low_buf[16] = {0};
        size_t high_len = dot - str;
        if (high_len == 0 || high_len >= sizeof(high_buf)) return false;
        memcpy(high_buf, str, high_len);

        const char *low_ptr = dot + 1;
        size_t low_len = strlen(low_ptr);
        // Trim trailing whitespace
        while (low_len > 0 && isspace((unsigned char)low_ptr[low_len - 1])) low_len--;
        if (low_len == 0 || low_len >= sizeof(low_buf)) return false;
        memcpy(low_buf, low_ptr, low_len);

        char *endp = NULL;
        unsigned long high = strtoul(high_buf, &endp, 10);
        if (*endp != '\0' || high > 65535) return false;

        unsigned long low = strtoul(low_buf, &endp, 10);
        if (*endp != '\0' || low > 65535) return false;

        *out_asn = (uint32_t)((high << 16) | low);
        return true;
    }

    char *endp = NULL;
    unsigned long val = strtoul(str, &endp, 10);
    while (endp && isspace((unsigned char)*endp)) endp++;
    if (*endp != '\0' || val > 4294967295UL) return false;

    *out_asn = (uint32_t)val;
    return true;
}

bool bogon_check_asn_str(const char *str, const char **reason) {
    uint32_t asn = 0;
    if (!bogon_parse_asn(str, &asn)) {
        if (reason) *reason = "Invalid ASN syntax";
        return false;
    }
    return bogon_check_asn(asn, reason);
}

bool bogon_is_public_asn_str(const char *str) {
    return bogon_check_asn_str(str, NULL);
}

/* =========================================================================
 * IPv4 Functions
 * ========================================================================= */

bool bogon_check_ipv4(uint32_t ip, const char **reason) {
    for (size_t i = 0; i < sizeof(V4_RULES)/sizeof(V4_RULES[0]); i++) {
        if ((ip & V4_RULES[i].mask) == V4_RULES[i].net) {
            if (reason) *reason = V4_RULES[i].reason;
            return false;
        }
    }
    if (reason) *reason = NULL;
    return true;
}

bool bogon_is_public_ipv4(uint32_t ip) {
    return bogon_check_ipv4(ip, NULL);
}

/* =========================================================================
 * IPv6 Functions
 * ========================================================================= */

static inline bool v6_match_prefix(const uint8_t octets[16], const uint8_t net[16], uint8_t bits) {
    uint8_t full_bytes = bits / 8;
    if (full_bytes > 0 && memcmp(octets, net, full_bytes) != 0) {
        return false;
    }
    uint8_t rem_bits = bits % 8;
    if (rem_bits > 0) {
        uint8_t mask = (uint8_t)(~((1U << (8 - rem_bits)) - 1U));
        if ((octets[full_bytes] & mask) != (net[full_bytes] & mask)) {
            return false;
        }
    }
    return true;
}

bool bogon_check_ipv6(const uint8_t octets[16], const char **reason) {
    if (!octets) return false;

    // Check for IPv4-mapped IPv6 (::ffff:0:0/96)
    static const uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    if (memcmp(octets, v4_mapped_prefix, 12) == 0) {
        uint32_t v4 = ((uint32_t)octets[12] << 24) |
                      ((uint32_t)octets[13] << 16) |
                      ((uint32_t)octets[14] << 8)  |
                       (uint32_t)octets[15];
        return bogon_check_ipv4(v4, reason);
    }

    // Explicit V6 bogon rules
    for (size_t i = 0; i < sizeof(V6_RULES)/sizeof(V6_RULES[0]); i++) {
        if (v6_match_prefix(octets, V6_RULES[i].net, V6_RULES[i].mask_bits)) {
            if (reason) *reason = V6_RULES[i].reason;
            return false;
        }
    }

    // ::1 Loopback
    static const uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(octets, loopback, 16) == 0) {
        if (reason) *reason = "RFC 4291 (Loopback)";
        return false;
    }

    // :: Unspecified
    static const uint8_t unspecified[16] = {0};
    if (memcmp(octets, unspecified, 16) == 0) {
        if (reason) *reason = "RFC 4291 (Unspecified)";
        return false;
    }

    // fe80::/10 Link-Local
    if (octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80) {
        if (reason) *reason = "RFC 4291 (Link-Local)";
        return false;
    }

    // fc00::/7 Unique Local (ULA)
    if ((octets[0] & 0xFE) == 0xFC) {
        if (reason) *reason = "RFC 4193 (Unique Local Address / ULA)";
        return false;
    }

    // ff00::/8 Multicast
    if (octets[0] == 0xFF) {
        if (reason) *reason = "RFC 4291 (Multicast)";
        return false;
    }

    // Only 2000::/3 is globally routable
    if (octets[0] < 0x20 || octets[0] > 0x3F) {
        if (reason) *reason = "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)";
        return false;
    }

    if (reason) *reason = NULL;
    return true;
}

bool bogon_is_public_ipv6(const uint8_t octets[16]) {
    return bogon_check_ipv6(octets, NULL);
}

/* =========================================================================
 * String IP Parsing & Validation
 * ========================================================================= */

bool bogon_check_ip_str(const char *ip_str, const char **reason) {
    if (!ip_str) {
        if (reason) *reason = "Invalid IP address syntax";
        return false;
    }

    // Trim leading whitespace
    while (isspace((unsigned char)*ip_str)) ip_str++;
    if (*ip_str == '\0') {
        if (reason) *reason = "Invalid IP address syntax";
        return false;
    }

    // Copy to temporary buffer to trim trailing whitespace
    char buf[128];
    size_t len = strlen(ip_str);
    while (len > 0 && isspace((unsigned char)ip_str[len - 1])) len--;
    if (len >= sizeof(buf)) {
        if (reason) *reason = "Invalid IP address syntax";
        return false;
    }
    memcpy(buf, ip_str, len);
    buf[len] = '\0';

    // Try IPv4 first
    struct in_addr in4;
    if (inet_pton(AF_INET, buf, &in4) == 1) {
        uint32_t host_ip = ntohl(in4.s_addr);
        return bogon_check_ipv4(host_ip, reason);
    }

    // Try IPv6
    struct in6_addr in6;
    if (inet_pton(AF_INET6, buf, &in6) == 1) {
        return bogon_check_ipv6(in6.s6_addr, reason);
    }

    if (reason) *reason = "Invalid IP address syntax";
    return false;
}

bool bogon_is_public_ip_str(const char *ip_str) {
    return bogon_check_ip_str(ip_str, NULL);
}

/* =========================================================================
 * BGP Announcement Prefix Validation
 * ========================================================================= */

bool bogon_valid_public_prefix_v4(uint32_t ip, uint8_t prefix_len) {
    if (prefix_len < 8 || prefix_len > 24) return false;
    uint32_t mask = v4_calc_mask(prefix_len);
    if ((ip & mask) != ip) {
        // Host bits set
        return false;
    }
    return bogon_is_public_ipv4(ip);
}

bool bogon_valid_public_prefix_v6(const uint8_t octets[16], uint8_t prefix_len) {
    if (!octets) return false;

    // Check for IPv4-mapped IPv6
    static const uint8_t v4_mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    if (memcmp(octets, v4_mapped, 12) == 0) {
        uint32_t v4 = ((uint32_t)octets[12] << 24) |
                      ((uint32_t)octets[13] << 16) |
                      ((uint32_t)octets[14] << 8)  |
                       (uint32_t)octets[15];
        uint8_t v4_len = prefix_len >= 96 ? prefix_len - 96 : prefix_len;
        return bogon_valid_public_prefix_v4(v4, v4_len);
    }

    if (prefix_len < 16 || prefix_len > 48) return false;

    // Check host bits are zero
    uint8_t full_bytes = prefix_len / 8;
    uint8_t rem_bits = prefix_len % 8;

    if (rem_bits > 0) {
        uint8_t host_mask = (uint8_t)((1U << (8 - rem_bits)) - 1U);
        if ((octets[full_bytes] & host_mask) != 0) return false;
        full_bytes++;
    }
    for (size_t i = full_bytes; i < 16; i++) {
        if (octets[i] != 0) return false;
    }

    return bogon_is_public_ipv6(octets);
}

bool bogon_valid_public_prefix_str(const char *cidr_str) {
    if (!cidr_str) return false;

    const char *slash = strchr(cidr_str, '/');
    if (!slash) return false;

    char ip_buf[128];
    size_t ip_len = slash - cidr_str;
    if (ip_len == 0 || ip_len >= sizeof(ip_buf)) return false;
    memcpy(ip_buf, cidr_str, ip_len);
    ip_buf[ip_len] = '\0';

    char *endp = NULL;
    unsigned long len = strtoul(slash + 1, &endp, 10);
    while (endp && isspace((unsigned char)*endp)) endp++;
    if (*endp != '\0' || len > 128) return false;

    struct in_addr in4;
    if (inet_pton(AF_INET, ip_buf, &in4) == 1) {
        return bogon_valid_public_prefix_v4(ntohl(in4.s_addr), (uint8_t)len);
    }

    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip_buf, &in6) == 1) {
        return bogon_valid_public_prefix_v6(in6.s6_addr, (uint8_t)len);
    }

    return false;
}
