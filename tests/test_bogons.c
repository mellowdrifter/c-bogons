/*
 * Unit tests for c-bogons
 */

#include "bogons.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int g_failures = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAILED: %s\n", (msg)); \
        g_failures++; \
    } \
} while (0)

#define TEST_ASSERT_FMT(cond, fmt, ...) do { \
    if (!(cond)) { \
        printf("FAILED: " fmt "\n", __VA_ARGS__); \
        g_failures++; \
    } \
} while (0)

static void test_version(void) {
    printf("Testing bogon_version()...\n");
    TEST_ASSERT_FMT(strcmp(bogon_version(), "1.4.1") == 0, "Version mismatch: got %s", bogon_version());
}

static void test_asn_validation(void) {
    printf("Testing ASN validation...\n");

    struct {
        uint32_t asn;
        bool want_public;
        const char *rfc;
    } cases[] = {
        { 0, false, "RFC 6483" },
        { 1, true, "" },
        { 15169, true, "" },
        { 23456, false, "RFC 6793" },
        { 64496, false, "RFC 5398" },
        { 64511, false, "RFC 5398" },
        { 64512, false, "RFC 1930" },
        { 65534, false, "RFC 1930" },
        { 65535, false, "RFC 7300" },
        { 65536, false, "RFC 5398" },
        { 65551, false, "RFC 5398" },
        { 65552, false, "RFC 7249" },
        { 131071, false, "RFC 7249" },
        { 131072, true, "" },
        { 4199999999U, true, "" },
        { 4200000000U, false, "RFC 6996" },
        { 4294967294U, false, "RFC 6996" },
        { 4294967295U, false, "RFC 7300" },
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        const char *reason = NULL;
        bool is_pub = bogon_check_asn(cases[i].asn, &reason);
        TEST_ASSERT_FMT(is_pub == cases[i].want_public, "ASN %u expected %d, got %d", cases[i].asn, cases[i].want_public, is_pub);
        if (!cases[i].want_public) {
            TEST_ASSERT_FMT(reason != NULL && strstr(reason, cases[i].rfc) != NULL,
                            "ASN %u reason expected %s, got %s", cases[i].asn, cases[i].rfc, reason ? reason : "NULL");
        } else {
            TEST_ASSERT_FMT(reason == NULL, "ASN %u expected NULL reason, got %s", cases[i].asn, reason);
        }
    }
}

static void test_asn_parsing(void) {
    printf("Testing ASN parsing...\n");

    uint32_t val = 0;
    TEST_ASSERT(bogon_parse_asn("15169", &val) && val == 15169, "parse 15169");
    TEST_ASSERT(bogon_parse_asn("AS15169", &val) && val == 15169, "parse AS15169");
    TEST_ASSERT(bogon_parse_asn("as15169", &val) && val == 15169, "parse as15169");
    TEST_ASSERT(bogon_parse_asn("1.0", &val) && val == 65536, "parse 1.0 (asdot)");
    TEST_ASSERT(bogon_parse_asn("1.1", &val) && val == 65537, "parse 1.1 (asdot)");
    TEST_ASSERT(bogon_parse_asn("AS1.0", &val) && val == 65536, "parse AS1.0");

    TEST_ASSERT(!bogon_parse_asn("", &val), "parse empty");
    TEST_ASSERT(!bogon_parse_asn("ghost", &val), "parse ghost");
    TEST_ASSERT(!bogon_parse_asn("1.2.3", &val), "parse 1.2.3");
}

static void test_ip_validation(void) {
    printf("Testing IP validation...\n");

    struct {
        const char *ip;
        bool want_public;
    } cases[] = {
        // IPv4 Global Unicast
        { "1.1.1.1", true },
        { "8.8.8.8", true },
        { "192.0.1.1", true },
        // IPv4 Bogons
        { "0.0.0.1", false },
        { "127.0.0.1", false },
        { "10.1.2.3", false },
        { "172.16.1.1", false },
        { "172.31.255.255", false },
        { "192.168.1.1", false },
        { "100.64.0.1", false },
        { "169.254.1.1", false },
        { "192.0.0.1", false },
        { "192.0.2.1", false },
        { "198.51.100.1", false },
        { "203.0.113.1", false },
        { "198.18.0.1", false },
        { "198.19.255.255", false },
        { "224.0.0.1", false },
        { "240.0.0.1", false },
        { "255.255.255.255", false },
        { "192.88.99.1", false },
        { "192.31.196.1", false },
        { "192.52.193.1", false },
        { "192.0.0.170", false },
        { "192.0.0.9", false },
        // IPv6 Global Unicast
        { "2600::", true },
        { "2001:4860:4860::8888", true },
        { "3fff::1", true },
        // IPv6 Bogons
        { "::1", false },
        { "::", false },
        { "fe80::1", false },
        { "fc00::1", false },
        { "fd00::1", false },
        { "2001::1", false },
        { "2001:1:2::3", false },
        { "2001:10::1", false },
        { "2001:2::1", false },
        { "2001:db8::1", false },
        { "2002::1", false },
        { "100::1", false },
        { "64:ff9b::1", false },
        { "64:ff9b:1::1", false },
        { "3ffe::1", false },
        { "ff02::1", false },
        { "2620:4f:8000::1", false },
        { "2001:30::1", false },
        { "2001:3::1", false },
        { "4000::1", false },
        // Mapped IPv6
        { "::ffff:1.2.3.4", true },
        { "::ffff:10.0.0.1", false },
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        const char *reason = NULL;
        bool is_pub = bogon_check_ip_str(cases[i].ip, &reason);
        TEST_ASSERT_FMT(is_pub == cases[i].want_public, "IP %s expected %d, got %d (reason: %s)",
                        cases[i].ip, cases[i].want_public, is_pub, reason ? reason : "none");
    }

    // Malformed IP strings
    TEST_ASSERT(!bogon_is_public_ip_str(""), "empty IP");
    TEST_ASSERT(!bogon_is_public_ip_str("ghost"), "ghost IP");
    TEST_ASSERT(!bogon_is_public_ip_str("1.1.1.1.1"), "1.1.1.1.1");
    TEST_ASSERT(!bogon_is_public_ip_str(":::"), ":::");
    TEST_ASSERT(!bogon_is_public_ip_str("2001:db8::z"), "invalid hex");
}

static void test_bgp_prefix_validation(void) {
    printf("Testing BGP prefix validation...\n");

    // Valid IPv4
    TEST_ASSERT(bogon_valid_public_prefix_str("8.8.8.0/24"), "valid 8.8.8.0/24");
    TEST_ASSERT(bogon_valid_public_prefix_str("1.1.1.0/24"), "valid 1.1.1.0/24");
    TEST_ASSERT(bogon_valid_public_prefix_str("12.0.0.0/8"), "valid 12.0.0.0/8");

    // Invalid IPv4
    TEST_ASSERT(!bogon_valid_public_prefix_str("8.8.8.8/32"), "too long v4");
    TEST_ASSERT(!bogon_valid_public_prefix_str("8.0.0.0/7"), "too short v4");
    TEST_ASSERT(!bogon_valid_public_prefix_str("10.0.0.0/8"), "private v4");
    TEST_ASSERT(!bogon_valid_public_prefix_str("8.8.8.1/24"), "host bits v4");

    // Valid IPv6
    TEST_ASSERT(bogon_valid_public_prefix_str("2600::/16"), "valid 2600::/16");
    TEST_ASSERT(bogon_valid_public_prefix_str("2001:4860::/32"), "valid 2001:4860::/32");
    TEST_ASSERT(bogon_valid_public_prefix_str("2a0d:1a40::/32"), "valid 2a0d:1a40::/32");
    TEST_ASSERT(bogon_valid_public_prefix_str("2001:4860:4860::/48"), "valid /48 v6");

    // Invalid IPv6
    TEST_ASSERT(!bogon_valid_public_prefix_str("2600::/15"), "too short v6");
    TEST_ASSERT(!bogon_valid_public_prefix_str("2600::/64"), "too long v6");
    TEST_ASSERT(!bogon_valid_public_prefix_str("2001:db8::/32"), "doc v6");
    TEST_ASSERT(!bogon_valid_public_prefix_str("2001:4860::1/32"), "host bits v6");
}

int main(void) {
    test_version();
    test_asn_validation();
    test_asn_parsing();
    test_ip_validation();
    test_bgp_prefix_validation();

    if (g_failures == 0) {
        printf("ALL TESTS PASSED!\n");
        return 0;
    } else {
        printf("%d TESTS FAILED!\n", g_failures);
        return 1;
    }
}
