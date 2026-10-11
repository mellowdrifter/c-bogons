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

#ifndef BOGONS_H
#define BOGONS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BOGONS_VERSION "1.4.1"
#define BOGONS_VERSION_MAJOR 1
#define BOGONS_VERSION_MINOR 4
#define BOGONS_VERSION_PATCH 1

/**
 * Returns the version string of the bogons library ("1.4.1").
 */
const char *bogon_version(void);

/* =========================================================================
 * ASN Checking & Parsing
 * ========================================================================= */

/**
 * Checks whether an ASN is valid and publicly routable.
 *
 * @param asn 32-bit autonomous system number.
 * @param reason If non-NULL and the ASN is a bogon, receives a pointer to a
 *               static string describing the RFC/reason. If public, set to NULL.
 * @return true if valid and publicly routable, false if bogon/reserved.
 */
bool bogon_check_asn(uint32_t asn, const char **reason);

/**
 * Convenience wrapper returning whether an ASN is valid and publicly routable.
 */
bool bogon_is_public_asn(uint32_t asn);

/**
 * Parses an ASN from a string. Supports decimal ("15169"), "AS"/"as" prefix
 * ("AS15169"), and 4-byte asdot notation ("1.0").
 *
 * @param str Input string.
 * @param out_asn Output pointer to receive the parsed 32-bit ASN.
 * @return true on successful parse, false on invalid syntax.
 */
bool bogon_parse_asn(const char *str, uint32_t *out_asn);

/**
 * Checks whether an ASN string is valid and publicly routable.
 *
 * @param str Input string.
 * @param reason Output pointer to receive static RFC description or error.
 * @return true if valid and public, false if invalid syntax or bogon.
 */
bool bogon_check_asn_str(const char *str, const char **reason);

/**
 * Convenience wrapper checking whether an ASN string is publicly routable.
 */
bool bogon_is_public_asn_str(const char *str);

/* =========================================================================
 * IP Validation (Zero Heap Allocation)
 * ========================================================================= */

/**
 * Checks whether an IPv4 address is publicly routable.
 *
 * @param ip_host_order IPv4 address in host byte order (e.g. 0x08080808 for 8.8.8.8).
 * @param reason If non-NULL and address is a bogon, receives static RFC description.
 * @return true if public, false if bogon.
 */
bool bogon_check_ipv4(uint32_t ip_host_order, const char **reason);

/**
 * Reports whether an IPv4 address is publicly routable.
 */
bool bogon_is_public_ipv4(uint32_t ip_host_order);

/**
 * Checks whether an IPv6 address is publicly routable.
 * Automatically unmaps IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
 *
 * @param octets 16-byte array containing the IPv6 address in network byte order.
 * @param reason If non-NULL and address is a bogon, receives static RFC description.
 * @return true if public, false if bogon.
 */
bool bogon_check_ipv6(const uint8_t octets[16], const char **reason);

/**
 * Reports whether an IPv6 address is publicly routable.
 */
bool bogon_is_public_ipv6(const uint8_t octets[16]);

/**
 * Parses an IPv4 or IPv6 string and checks whether it is publicly routable.
 *
 * @param ip_str String representation of the IP address.
 * @param reason Output pointer for RFC reason or error description.
 * @return true if valid and public, false if invalid syntax or bogon.
 */
bool bogon_check_ip_str(const char *ip_str, const char **reason);

/**
 * Reports whether an IP string parses as a publicly routable IP.
 */
bool bogon_is_public_ip_str(const char *ip_str);

/* =========================================================================
 * BGP Announcement Validation
 * ========================================================================= */

/**
 * Validates an IPv4 network prefix for BGP announcement:
 * - Prefix length must be between 8 and 24 (inclusive).
 * - Host bits must be zero (strict network normalization).
 * - Must not fall in bogon address space.
 */
bool bogon_valid_public_prefix_v4(uint32_t ip_host_order, uint8_t prefix_len);

/**
 * Validates an IPv6 network prefix for BGP announcement:
 * - Prefix length must be between 16 and 48 (inclusive).
 * - Host bits must be zero (strict network normalization).
 * - Must not fall in bogon address space.
 */
bool bogon_valid_public_prefix_v6(const uint8_t octets[16], uint8_t prefix_len);

/**
 * Parses and validates a CIDR string (e.g. "8.8.8.0/24", "2600::/16") for BGP announcement.
 */
bool bogon_valid_public_prefix_str(const char *cidr_str);

#ifdef __cplusplus
}
#endif

#endif /* BOGONS_H */
