/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer Harness: Battery Sysfs Parser (fuzz/fuzz_battery_sysfs.c)
 * Fuzzes parsing of Linux power_supply sysfs nodes and uevent properties.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

typedef enum {
    BATTERY_STATUS_UNKNOWN = 0,
    BATTERY_STATUS_CHARGING,
    BATTERY_STATUS_DISCHARGING,
    BATTERY_STATUS_NOT_CHARGING,
    BATTERY_STATUS_FULL
} battery_status_t;

typedef struct {
    char name[32];
    int capacity_pct;
    int charge_limit_pct;
    int temp_deci_celsius;
    long voltage_uv;
    long current_ua;
    battery_status_t status;
    bool present;
} battery_state_t;

static void trim_whitespace(char *str) {
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

static battery_status_t parse_battery_status(const char *status_str) {
    if (strcasecmp(status_str, "Charging") == 0) return BATTERY_STATUS_CHARGING;
    if (strcasecmp(status_str, "Discharging") == 0) return BATTERY_STATUS_DISCHARGING;
    if (strcasecmp(status_str, "Not charging") == 0) return BATTERY_STATUS_NOT_CHARGING;
    if (strcasecmp(status_str, "Full") == 0) return BATTERY_STATUS_FULL;
    return BATTERY_STATUS_UNKNOWN;
}

static int parse_sysfs_int(const char *buf, int min_val, int max_val, int def_val) {
    if (!buf) return def_val;
    char tmp[64];
    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    trim_whitespace(tmp);

    if (tmp[0] == '\0') return def_val;

    char *endptr = NULL;
    long val = strtol(tmp, &endptr, 10);
    if (endptr == tmp) return def_val;

    if (val < min_val) val = min_val;
    if (val > max_val) val = max_val;
    return (int)val;
}

static void parse_uevent_buffer(const uint8_t *data, size_t size, battery_state_t *st) {
    char line[256];
    size_t line_pos = 0;

    for (size_t i = 0; i <= size; i++) {
        char ch = (i < size) ? (char)data[i] : '\n';
        if (ch == '\n' || ch == '\r') {
            if (line_pos > 0) {
                line[line_pos] = '\0';
                char *eq = strchr(line, '=');
                if (eq) {
                    *eq = '\0';
                    char *key = line;
                    char *val = eq + 1;
                    trim_whitespace(key);
                    trim_whitespace(val);

                    if (strcmp(key, "POWER_SUPPLY_NAME") == 0) {
                        strncpy(st->name, val, sizeof(st->name) - 1);
                    } else if (strcmp(key, "POWER_SUPPLY_STATUS") == 0) {
                        st->status = parse_battery_status(val);
                    } else if (strcmp(key, "POWER_SUPPLY_CAPACITY") == 0) {
                        st->capacity_pct = parse_sysfs_int(val, 0, 100, 0);
                    } else if (strcmp(key, "POWER_SUPPLY_CHARGE_CONTROL_LIMIT_MAX") == 0 ||
                               strcmp(key, "POWER_SUPPLY_CHARGE_STOP_THRESHOLD") == 0) {
                        st->charge_limit_pct = parse_sysfs_int(val, 20, 100, 80);
                    } else if (strcmp(key, "POWER_SUPPLY_TEMP") == 0) {
                        st->temp_deci_celsius = parse_sysfs_int(val, -500, 1500, 250);
                    } else if (strcmp(key, "POWER_SUPPLY_VOLTAGE_NOW") == 0) {
                        st->voltage_uv = strtol(val, NULL, 10);
                    } else if (strcmp(key, "POWER_SUPPLY_CURRENT_NOW") == 0) {
                        st->current_ua = strtol(val, NULL, 10);
                    } else if (strcmp(key, "POWER_SUPPLY_PRESENT") == 0) {
                        st->present = (atoi(val) == 1);
                    }
                }
                line_pos = 0;
            }
        } else {
            if (line_pos < sizeof(line) - 1) {
                line[line_pos++] = ch;
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    battery_state_t state;
    memset(&state, 0, sizeof(state));
    state.charge_limit_pct = 80;

    // Test 1: Direct single-value sysfs node integer parsing (e.g. charge limit)
    char null_term[128];
    size_t copy_sz = size < sizeof(null_term) - 1 ? size : sizeof(null_term) - 1;
    memcpy(null_term, data, copy_sz);
    null_term[copy_sz] = '\0';

    int limit = parse_sysfs_int(null_term, 20, 100, 80);
    (void)limit;

    // Test 2: Direct status string matching
    battery_status_t st = parse_battery_status(null_term);
    (void)st;

    // Test 3: Multi-line uevent parsing
    parse_uevent_buffer(data, size, &state);

    return 0;
}
