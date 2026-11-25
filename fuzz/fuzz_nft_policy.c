/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer Harness: TOML Egress Policy Parser (fuzz/fuzz_nft_policy.c)
 * Fuzzes the C parser for declarative mobile egress policies (security/egress/policy/*.toml).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

typedef struct {
    char app_id[128];
    char app_name[128];
    char app_type[64];
    char systemd_unit[128];
    char mode[64];
    char allowed_interfaces[8][32];
    int interface_count;
    char allowed_destinations[16][128];
    int dest_count;
    char dns_policy[64];
    int kill_switch;
    int anti_features_visible;
} egress_policy_t;

static void trim_whitespace(char *str) {
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);

    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

static void extract_quoted_string(const char *in, char *out, size_t out_max) {
    out[0] = '\0';
    const char *q1 = strchr(in, '"');
    if (!q1) q1 = strchr(in, '\'');
    if (!q1) return;
    char quote_char = *q1;
    const char *q2 = strchr(q1 + 1, quote_char);
    if (!q2) return;
    size_t len = (size_t)(q2 - q1 - 1);
    if (len >= out_max) len = out_max - 1;
    memcpy(out, q1 + 1, len);
    out[len] = '\0';
}

static void parse_string_array(const char *in, char out_arr[][32], int *count, int max_items) {
    *count = 0;
    const char *p = strchr(in, '[');
    if (!p) return;
    const char *end = strchr(p, ']');
    if (!end) return;

    p++;
    while (p < end && *count < max_items) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (p >= end) break;
        if (*p == '"' || *p == '\'') {
            char quote = *p++;
            const char *q_end = strchr(p, quote);
            if (!q_end || q_end > end) break;
            size_t len = (size_t)(q_end - p);
            if (len >= 32) len = 31;
            memcpy(out_arr[*count], p, len);
            out_arr[*count][len] = '\0';
            (*count)++;
            p = q_end + 1;
        } else {
            p++;
        }
    }
}

static int parse_toml_policy(const char *data, size_t size, egress_policy_t *policy) {
    if (size == 0 || size > 65536) return 0;

    memset(policy, 0, sizeof(*policy));
    char *copy = (char *)malloc(size + 1);
    if (!copy) return 0;
    memcpy(copy, data, size);
    copy[size] = '\0';

    char current_section[64] = {0};
    char *saveptr = NULL;
    char *line = strtok_r(copy, "\r\n", &saveptr);

    while (line) {
        trim_whitespace(line);
        if (line[0] == '#' || line[0] == '\0') {
            line = strtok_r(NULL, "\r\n", &saveptr);
            continue;
        }

        // Section header
        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            size_t s_len = strlen(line) - 2;
            if (s_len < sizeof(current_section)) {
                memcpy(current_section, line + 1, s_len);
                current_section[s_len] = '\0';
                trim_whitespace(current_section);
            }
            line = strtok_r(NULL, "\r\n", &saveptr);
            continue;
        }

        // Key = Value
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            char *key = line;
            char *val = eq + 1;
            trim_whitespace(key);
            trim_whitespace(val);

            if (strcmp(current_section, "app") == 0) {
                if (strcmp(key, "id") == 0) extract_quoted_string(val, policy->app_id, sizeof(policy->app_id));
                else if (strcmp(key, "name") == 0) extract_quoted_string(val, policy->app_name, sizeof(policy->app_name));
                else if (strcmp(key, "type") == 0) extract_quoted_string(val, policy->app_type, sizeof(policy->app_type));
                else if (strcmp(key, "systemd_unit") == 0) extract_quoted_string(val, policy->systemd_unit, sizeof(policy->systemd_unit));
            } else if (strcmp(current_section, "network") == 0) {
                if (strcmp(key, "mode") == 0) {
                    extract_quoted_string(val, policy->mode, sizeof(policy->mode));
                } else if (strcmp(key, "allowed_interfaces") == 0) {
                    parse_string_array(val, policy->allowed_interfaces, &policy->interface_count, 8);
                } else if (strcmp(key, "dns_policy") == 0) {
                    extract_quoted_string(val, policy->dns_policy, sizeof(policy->dns_policy));
                } else if (strcmp(key, "kill_switch") == 0) {
                    policy->kill_switch = (strstr(val, "true") != NULL);
                } else if (strcmp(key, "anti_features_visible") == 0) {
                    policy->anti_features_visible = (strstr(val, "true") != NULL);
                }
            }
        }

        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    free(copy);
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    egress_policy_t policy;
    parse_toml_policy((const char *)data, size, &policy);

    return 0;
}
