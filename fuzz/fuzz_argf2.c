/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer Harness: ARGF/2 Binary Header & Record Parser (fuzz/fuzz_argf2.c)
 * Fuzzes the 128-byte ARGF/2 binary segment header and variable payload records.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define ARGF_HDR_LEN 128
#define ARGF_MAGIC 0x46475241 // "ARGF" in little-endian

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;         // 4 bytes: "ARGF"
    uint8_t  ver;           // 1 byte
    uint8_t  cls;           // 1 byte: 0x4B (K), 0x53 (S), 0x41 (A)
    uint16_t type;          // 2 bytes
    uint16_t flags;         // 2 bytes: bit 0: SEALED, bit 1: REDACTED, bit 2: BEST_EFFORT
    uint16_t payload_len;   // 2 bytes: max 4096
    uint32_t unc_ns;        // 4 bytes
    uint64_t seq;           // 8 bytes: monotonic record sequence
    uint64_t mono_ns;       // 8 bytes: monotonic timestamp
    uint64_t wall_ns;       // 8 bytes: realtime timestamp
    uint64_t cgroup_id;     // 8 bytes
    uint32_t pid;           // 4 bytes
    uint32_t tgid;          // 4 bytes
    uint32_t uid;           // 4 bytes
    uint32_t gid;           // 4 bytes
    uint64_t grant_id;      // 8 bytes
    uint64_t producer_id;   // 8 bytes
    uint8_t  payload_root[32]; // 32 bytes: BLAKE3 payload root
    uint64_t nonce;         // 8 bytes
    uint8_t  reserved[8];   // 8 bytes
} argf_header_t;
#pragma pack(pop)

static int parse_argf2_record(const uint8_t *data, size_t size) {
    if (size < ARGF_HDR_LEN) return 0;

    const argf_header_t *hdr = (const argf_header_t *)data;

    // Verify magic
    if (hdr->magic != ARGF_MAGIC) {
        return 0;
    }

    // Class check
    if (hdr->cls != 0x4B && hdr->cls != 0x53 && hdr->cls != 0x41) {
        return 0;
    }

    // Payload bounds check
    uint16_t payload_len = hdr->payload_len;
    if (payload_len > 4096) {
        return 0;
    }

    if (size < ARGF_HDR_LEN + (size_t)payload_len) {
        return 0; // Truncated payload
    }

    const uint8_t *payload = data + ARGF_HDR_LEN;
    size_t offset = 0;

    // Parse variable field records inside payload: [tag: 2 bytes, len: 2 bytes, value: len bytes]
    int fields_parsed = 0;
    while (offset + 4 <= payload_len && fields_parsed < 32) {
        uint16_t tag = (uint16_t)(payload[offset] | (payload[offset + 1] << 8));
        uint16_t len = (uint16_t)(payload[offset + 2] | (payload[offset + 3] << 8));
        offset += 4;

        if (offset + len > payload_len) {
            break; // Malformed field
        }

        // Process field data dummy sink
        volatile uint8_t sum = 0;
        for (size_t i = 0; i < len; i++) {
            sum ^= payload[offset + i];
        }
        (void)sum;
        (void)tag;

        offset += len;
        fields_parsed++;
    }

    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    parse_argf2_record(data, size);

    return 0;
}
