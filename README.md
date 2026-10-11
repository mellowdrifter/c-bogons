# libbogons (C)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Lean, high-performance, zero-allocation C library (C99/C11) for validating IP address, subnet prefix, and ASN [bogons](https://en.wikipedia.org/wiki/Bogon_filtering) with RFC descriptions.

Designed for network routing engines (BIRD, FRR), packet sniffers, and Linux kernel **eBPF / XDP** fast-path filters.

## Features

- **Zero Dynamic Memory Allocation**: Never calls `malloc`, `free`, or `realloc`. All operations execute on the stack or in CPU registers.
- **eBPF & Kernel Friendly**: Safe for high-frequency dataplane execution with zero runtime dependencies.
- **IP Validation & Reasons**: Validates IPv4 (host-order `uint32_t`), IPv6 (`uint8_t[16]`), or strings (`bogon_check_ip_str`).
- **ASN Validation & Parsing**: Validates 32-bit AS numbers with static RFC descriptions; supports `asplain` ("15169"), `AS`-prefixed ("AS15169"), and `asdot` ("1.0") notation (`bogon_parse_asn`, `bogon_check_asn`).
- **BGP Announcement Validation**: Enforces BGP routing limits (/8–/24 for IPv4, /16–/48 for IPv6) and rejects prefixes with host bits set (`bogon_valid_public_prefix_str`).
- **Standard Packaging**: Includes `Makefile` generating static `libbogons.a`, shared `libbogons.so`, and `bogons.pc` for `pkg-config`.

## Multi-Language Implementations

The `bogons` library is maintained with 100% feature parity, RFC attribution, and synchronized versioning across 6 languages:

| Language | Repository (GitHub) | Package Registry | Installation |
|---|---|---|---|
| **Go** | [mellowdrifter/bogons](https://github.com/mellowdrifter/bogons) | [pkg.go.dev](https://pkg.go.dev/github.com/mellowdrifter/bogons) | `go get github.com/mellowdrifter/bogons` |
| **Python** | [mellowdrifter/python-bogons](https://github.com/mellowdrifter/python-bogons) | [PyPI](https://pypi.org/project/bogons/) | `pip install bogons` |
| **Rust** | [mellowdrifter/rust-bogons](https://github.com/mellowdrifter/rust-bogons) | [crates.io](https://crates.io/crates/bogons) | `cargo add bogons` |
| **C** | [mellowdrifter/c-bogons](https://github.com/mellowdrifter/c-bogons) | [libbogons](https://github.com/mellowdrifter/c-bogons/releases) | Single-header / `make install` |
| **C++** | [mellowdrifter/cpp-bogons](https://github.com/mellowdrifter/cpp-bogons) | [CMake / Header-only](https://github.com/mellowdrifter/cpp-bogons/releases) | `#include <bogons/bogons.hpp>` |
| **TypeScript / JS** | [mellowdrifter/ts-bogons](https://github.com/mellowdrifter/ts-bogons) | [npm](https://www.npmjs.com/package/bogons) | `npm install bogons` |

## Building & Installation

```bash
make
make test
sudo make install PREFIX=/usr/local
```

Or consume via `pkg-config`:

```bash
gcc main.c $(pkg-config --cflags --libs bogons)
```

## Usage

```c
#include <bogons.h>
#include <stdio.h>

int main(void) {
    const char *reason = NULL;

    // IP Validation with RFC Reason
    if (!bogon_check_ip_str("10.0.0.1", &reason)) {
        printf("10.0.0.1 is a bogon: %s\n", reason);
        // Output: 10.0.0.1 is a bogon: RFC 1918 (Private-Use)
    }

    // ASN Validation
    if (!bogon_check_asn(64512, &reason)) {
        printf("AS64512 is a bogon: %s\n", reason);
        // Output: AS64512 is a bogon: RFC 1930 / RFC 6996 (Private-Use 16-bit)
    }

    // ASN Parsing (supports AS prefix and asdot notation)
    uint32_t asn = 0;
    bogon_parse_asn("AS1.0", &asn);
    printf("AS1.0 = %u\n", asn); // 65536

    // BGP Announcement Prefix Validation
    bool valid = bogon_valid_public_prefix_str("8.8.8.0/24"); // true
    bool bad_host = bogon_valid_public_prefix_str("8.8.8.1/24"); // false (host bits set)

    return 0;
}
```

## License

Licensed under the Apache License, Version 2.0.
