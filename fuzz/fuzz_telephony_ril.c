/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer Harness: Telephony RIL & SMS PDU Parser (fuzz/fuzz_telephony_ril.c)
 * Fuzzes SMS PDU decoders (7-bit GSM, UCS-2, TP-OA) and ModemManager/RIL responses.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

// Decode semi-octets (swapped nibbles in GSM addresses)
static void parse_semi_octets(const uint8_t *p, size_t len, char *out, size_t out_max) {
    size_t out_idx = 0;
    for (size_t i = 0; i < len && out_idx + 2 < out_max; i++) {
        uint8_t low = p[i] & 0x0F;
        uint8_t high = (p[i] >> 4) & 0x0F;
        if (low <= 9) out[out_idx++] = (char)('0' + low);
        else if (low == 0x0A) out[out_idx++] = '*';
        else if (low == 0x0B) out[out_idx++] = '#';
        if (high <= 9) out[out_idx++] = (char)('0' + high);
        else if (high == 0x0A) out[out_idx++] = '*';
        else if (high == 0x0B) out[out_idx++] = '#';
    }
    out[out_idx] = '\0';
}

// GSM 7-bit septet to ASCII unpacker
static void unpack_7bit_gsm(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    size_t out_idx = 0;
    uint8_t shift = 0;
    uint8_t carry = 0;

    for (size_t i = 0; i < in_len && out_idx + 1 < out_max; i++) {
        uint8_t cur = in[i];
        uint8_t ch = ((cur << shift) | carry) & 0x7F;
        out[out_idx++] = (ch >= 32 && ch <= 126) ? (char)ch : '.';
        carry = cur >> (7 - shift);
        shift++;

        if (shift == 7) {
            if (out_idx + 1 < out_max) {
                out[out_idx++] = (carry >= 32 && carry <= 126) ? (char)carry : '.';
            }
            shift = 0;
            carry = 0;
        }
    }
    out[out_idx] = '\0';
}

// Parses raw binary or hex SMS PDU
static int parse_sms_pdu(const uint8_t *pdu, size_t size) {
    if (size < 4) return 0;

    size_t offset = 0;

    // 1. SMSC Address Length
    uint8_t smsc_len = pdu[offset++];
    if (smsc_len > 0) {
        if (offset + smsc_len > size) return 0;
        uint8_t smsc_type = pdu[offset++];
        (void)smsc_type;
        char smsc_num[64] = {0};
        if (smsc_len > 1) {
            parse_semi_octets(&pdu[offset], smsc_len - 1, smsc_num, sizeof(smsc_num));
        }
        offset += (smsc_len - 1);
    }

    if (offset >= size) return 0;

    // 2. First Octet of SMS-DELIVER / SMS-SUBMIT
    uint8_t first_octet = pdu[offset++];
    int mti = first_octet & 0x03; // Message Type Indicator
    (void)mti;

    if (offset >= size) return 0;

    // 3. Originating / Destination Address Length (digits)
    uint8_t addr_digits = pdu[offset++];
    size_t addr_bytes = (addr_digits + 1) / 2;
    if (offset + 1 + addr_bytes > size) return 0;

    uint8_t addr_type = pdu[offset++];
    (void)addr_type;
    char sender_num[64] = {0};
    parse_semi_octets(&pdu[offset], addr_bytes, sender_num, sizeof(sender_num));
    offset += addr_bytes;

    if (offset + 2 > size) return 0;

    // 4. TP-PID and TP-DCS
    uint8_t tp_pid = pdu[offset++];
    uint8_t tp_dcs = pdu[offset++];
    (void)tp_pid;

    // 5. TP-SCTS (Service Center Time Stamp) 7 octets for DELIVER
    if (offset + 7 > size) return 0;
    char scts[32] = {0};
    parse_semi_octets(&pdu[offset], 7, scts, sizeof(scts));
    offset += 7;

    if (offset >= size) return 0;

    // 6. TP-UDL (User Data Length)
    uint8_t udl = pdu[offset++];
    if (offset > size) return 0;

    size_t remaining_ud = size - offset;
    char message_text[512] = {0};

    int coding = (tp_dcs >> 2) & 0x03;
    if (coding == 0) {
        // GSM 7-bit
        unpack_7bit_gsm(&pdu[offset], remaining_ud, message_text, sizeof(message_text));
    } else if (coding == 2) {
        // UCS-2 (16-bit)
        size_t ucs_len = remaining_ud / 2;
        size_t out_idx = 0;
        for (size_t u = 0; u < ucs_len && out_idx + 1 < sizeof(message_text); u++) {
            uint16_t code = (uint16_t)((pdu[offset + u * 2] << 8) | pdu[offset + u * 2 + 1]);
            message_text[out_idx++] = (code >= 32 && code <= 126) ? (char)code : '?';
        }
    } else {
        // 8-bit raw
        size_t copy_sz = remaining_ud < sizeof(message_text) - 1 ? remaining_ud : sizeof(message_text) - 1;
        memcpy(message_text, &pdu[offset], copy_sz);
    }

    return 1;
}

// Parses textual RIL unsolicited and AT command responses
static int parse_ril_response(const char *str, size_t len) {
    if (len == 0 || len > 4096) return 0;

    char buf[4096];
    size_t copy_sz = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, str, copy_sz);
    buf[copy_sz] = '\0';

    char *saveptr = NULL;
    char *line = strtok_r(buf, "\r\n", &saveptr);
    while (line) {
        while (*line == ' ') line++;
        if (strncmp(line, "+CSQ:", 5) == 0) {
            int rssi = 0, ber = 0;
            if (sscanf(line + 5, "%d,%d", &rssi, &ber) == 2) {
                (void)rssi; (void)ber;
            }
        } else if (strncmp(line, "+CREG:", 6) == 0 || strncmp(line, "+CEREG:", 7) == 0) {
            int n = 0, stat = 0;
            char lac[32] = {0}, ci[32] = {0};
            int act = 0;
            const char *p = strchr(line, ':');
            if (p) {
                sscanf(p + 1, "%d,%d,\"%31[^\"]\",\"%31[^\"]\",%d", &n, &stat, lac, ci, &act);
            }
        } else if (strncmp(line, "+CMGL:", 6) == 0 || strncmp(line, "+CMGR:", 6) == 0) {
            int idx = 0;
            char status[32] = {0}, sender[64] = {0};
            const char *p = strchr(line, ':');
            if (p) {
                sscanf(p + 1, "%d,\"%31[^\"]\",\"%63[^\"]\"", &idx, status, sender);
            }
        } else if (strncmp(line, "+COPS:", 6) == 0) {
            int mode = 0, fmt = 0;
            char oper[64] = {0};
            int act = 0;
            const char *p = strchr(line, ':');
            if (p) {
                sscanf(p + 1, "%d,%d,\"%63[^\"]\",%d", &mode, &fmt, oper, &act);
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Fuzz binary PDU parser
    parse_sms_pdu(data, size);

    // Fuzz string RIL parser
    parse_ril_response((const char *)data, size);

    return 0;
}
