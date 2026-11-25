/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer Harness: Waydroid PIF JSON Parser (fuzz/fuzz_pif_json.c)
 * Fuzzes JSON parsing and extraction of Play Integrity spoofing properties.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_TOKEN_LEN 256
#define MAX_DEPTH 16

typedef enum {
    TOK_ERROR = 0,
    TOK_EOF,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_COLON,
    TOK_COMMA,
    TOK_STRING,
    TOK_NUMBER,
    TOK_TRUE,
    TOK_FALSE,
    TOK_NULL
} token_type_t;

typedef struct {
    token_type_t type;
    char text[MAX_TOKEN_LEN];
    size_t text_len;
} token_t;

typedef struct {
    const uint8_t *src;
    size_t len;
    size_t pos;
} json_cursor_t;

typedef struct {
    char product[64];
    char device[64];
    char manufacturer[64];
    char brand[64];
    char model[64];
    char fingerprint[128];
    char security_patch[32];
    int first_api_level;
    bool meets_basic;
    bool meets_device;
    bool meets_strong;
} pif_profile_t;

static void skip_whitespace(json_cursor_t *c) {
    while (c->pos < c->len && isspace((unsigned char)c->src[c->pos])) {
        c->pos++;
    }
}

static token_t next_token(json_cursor_t *c) {
    token_t tok;
    memset(&tok, 0, sizeof(tok));
    skip_whitespace(c);

    if (c->pos >= c->len) {
        tok.type = TOK_EOF;
        return tok;
    }

    char ch = (char)c->src[c->pos++];
    switch (ch) {
        case '{': tok.type = TOK_LBRACE; return tok;
        case '}': tok.type = TOK_RBRACE; return tok;
        case '[': tok.type = TOK_LBRACKET; return tok;
        case ']': tok.type = TOK_RBRACKET; return tok;
        case ':': tok.type = TOK_COLON; return tok;
        case ',': tok.type = TOK_COMMA; return tok;
        case '"': {
            tok.type = TOK_STRING;
            size_t out = 0;
            while (c->pos < c->len) {
                char s = (char)c->src[c->pos++];
                if (s == '"') {
                    tok.text[out] = '\0';
                    tok.text_len = out;
                    return tok;
                }
                if (s == '\\') {
                    if (c->pos >= c->len) break;
                    s = (char)c->src[c->pos++];
                    if (s == 'n') s = '\n';
                    else if (s == 'r') s = '\r';
                    else if (s == 't') s = '\t';
                }
                if (out < sizeof(tok.text) - 1) {
                    tok.text[out++] = s;
                }
            }
            tok.text[out] = '\0';
            tok.text_len = out;
            return tok;
        }
        default:
            if (ch == '-' || isdigit((unsigned char)ch)) {
                tok.type = TOK_NUMBER;
                size_t out = 0;
                tok.text[out++] = ch;
                while (c->pos < c->len && (isdigit((unsigned char)c->src[c->pos]) || c->src[c->pos] == '.')) {
                    if (out < sizeof(tok.text) - 1) {
                        tok.text[out++] = (char)c->src[c->pos];
                    }
                    c->pos++;
                }
                tok.text[out] = '\0';
                tok.text_len = out;
                return tok;
            }
            if (isalpha((unsigned char)ch)) {
                size_t out = 0;
                tok.text[out++] = ch;
                while (c->pos < c->len && isalpha((unsigned char)c->src[c->pos])) {
                    if (out < sizeof(tok.text) - 1) {
                        tok.text[out++] = (char)c->src[c->pos];
                    }
                    c->pos++;
                }
                tok.text[out] = '\0';
                tok.text_len = out;
                if (strcmp(tok.text, "true") == 0) tok.type = TOK_TRUE;
                else if (strcmp(tok.text, "false") == 0) tok.type = TOK_FALSE;
                else if (strcmp(tok.text, "null") == 0) tok.type = TOK_NULL;
                else tok.type = TOK_ERROR;
                return tok;
            }
            tok.type = TOK_ERROR;
            return tok;
    }
}

static bool parse_value(json_cursor_t *c, int depth, pif_profile_t *prof, const char *cur_key);

static bool parse_object(json_cursor_t *c, int depth, pif_profile_t *prof) {
    if (depth >= MAX_DEPTH) return false;

    while (1) {
        token_t key_tok = next_token(c);
        if (key_tok.type == TOK_RBRACE) return true;
        if (key_tok.type != TOK_STRING) return false;

        token_t colon = next_token(c);
        if (colon.type != TOK_COLON) return false;

        char key[MAX_TOKEN_LEN];
        strncpy(key, key_tok.text, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';

        if (!parse_value(c, depth + 1, prof, key)) {
            return false;
        }

        token_t sep = next_token(c);
        if (sep.type == TOK_RBRACE) return true;
        if (sep.type != TOK_COMMA) return false;
    }
}

static bool parse_array(json_cursor_t *c, int depth, pif_profile_t *prof) {
    if (depth >= MAX_DEPTH) return false;

    while (1) {
        token_t tok = next_token(c);
        if (tok.type == TOK_RBRACKET) return true;
        if (tok.type == TOK_EOF || tok.type == TOK_ERROR) return false;

        // For arrays, continue
        token_t sep = next_token(c);
        if (sep.type == TOK_RBRACKET) return true;
        if (sep.type != TOK_COMMA) return false;
    }
}

static bool parse_value(json_cursor_t *c, int depth, pif_profile_t *prof, const char *cur_key) {
    token_t tok = next_token(c);

    switch (tok.type) {
        case TOK_LBRACE:
            return parse_object(c, depth, prof);
        case TOK_LBRACKET:
            return parse_array(c, depth, prof);
        case TOK_STRING:
            if (cur_key) {
                if (strcmp(cur_key, "PRODUCT") == 0) strncpy(prof->product, tok.text, sizeof(prof->product) - 1);
                else if (strcmp(cur_key, "DEVICE") == 0) strncpy(prof->device, tok.text, sizeof(prof->device) - 1);
                else if (strcmp(cur_key, "MANUFACTURER") == 0) strncpy(prof->manufacturer, tok.text, sizeof(prof->manufacturer) - 1);
                else if (strcmp(cur_key, "BRAND") == 0) strncpy(prof->brand, tok.text, sizeof(prof->brand) - 1);
                else if (strcmp(cur_key, "MODEL") == 0) strncpy(prof->model, tok.text, sizeof(prof->model) - 1);
                else if (strcmp(cur_key, "FINGERPRINT") == 0) strncpy(prof->fingerprint, tok.text, sizeof(prof->fingerprint) - 1);
                else if (strcmp(cur_key, "SECURITY_PATCH") == 0) strncpy(prof->security_patch, tok.text, sizeof(prof->security_patch) - 1);
            }
            return true;
        case TOK_NUMBER:
            if (cur_key && strcmp(cur_key, "FIRST_API_LEVEL") == 0) {
                prof->first_api_level = atoi(tok.text);
            }
            return true;
        case TOK_TRUE:
        case TOK_FALSE:
            if (cur_key) {
                bool val = (tok.type == TOK_TRUE);
                if (strcmp(cur_key, "MEETS_BASIC_INTEGRITY") == 0) prof->meets_basic = val;
                else if (strcmp(cur_key, "MEETS_DEVICE_INTEGRITY") == 0) prof->meets_device = val;
                else if (strcmp(cur_key, "MEETS_STRONG_INTEGRITY") == 0) prof->meets_strong = val;
            }
            return true;
        case TOK_NULL:
            return true;
        default:
            return false;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    json_cursor_t cursor;
    cursor.src = data;
    cursor.len = size;
    cursor.pos = 0;

    pif_profile_t profile;
    memset(&profile, 0, sizeof(profile));

    token_t first = next_token(&cursor);
    if (first.type == TOK_LBRACE) {
        parse_object(&cursor, 0, &profile);
    }

    return 0;
}
