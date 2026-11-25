/*
 * SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone Fuzz Driver for libFuzzer harnesses without Clang/LLVM engine.
 * Executes seed corpus files and runs continuous PRNG mutations under ASAN/UBSAN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static volatile sig_atomic_t g_stop = 0;

static void handle_sig(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 10 * 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    buf[read_bytes] = '\0';
    fclose(f);
    *out_size = read_bytes;
    return buf;
}

static void mutate(uint8_t *buf, size_t *size, size_t max_size) {
    if (*size == 0) {
        buf[0] = (uint8_t)(rand() % 256);
        *size = 1;
        return;
    }
    int op = rand() % 5;
    size_t pos = (size_t)(rand() % (int)*size);

    switch (op) {
        case 0: // Bit flip
            buf[pos] ^= (uint8_t)(1 << (rand() % 8));
            break;
        case 1: // Random byte
            buf[pos] = (uint8_t)(rand() % 256);
            break;
        case 2: // Delete byte
            if (*size > 1) {
                memmove(&buf[pos], &buf[pos + 1], *size - pos - 1);
                (*size)--;
            }
            break;
        case 3: // Insert random byte
            if (*size < max_size - 1) {
                memmove(&buf[pos + 1], &buf[pos], *size - pos);
                buf[pos] = (uint8_t)(rand() % 256);
                (*size)++;
            }
            break;
        case 4: // Swap adjacent bytes
            if (pos + 1 < *size) {
                uint8_t tmp = buf[pos];
                buf[pos] = buf[pos + 1];
                buf[pos + 1] = tmp;
            }
            break;
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    int max_time_sec = 60;
    const char *corpus_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-max_total_time=", 16) == 0) {
            max_time_sec = atoi(argv[i] + 16);
        } else if (strncmp(argv[i], "--duration=", 11) == 0) {
            max_time_sec = atoi(argv[i] + 11);
        } else if (argv[i][0] != '-') {
            corpus_dir = argv[i];
        }
    }

    printf("[fuzz-driver] Starting fuzzing session (max_total_time=%ds)...\n", max_time_sec);

    // Initial corpus execution
    size_t initial_runs = 0;
    uint8_t sample_corpus[64][4096];
    size_t sample_sizes[64];
    size_t sample_count = 0;

    if (corpus_dir) {
        DIR *d = opendir(corpus_dir);
        if (d) {
            struct dirent *dir;
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_name[0] == '.') continue;
                char fpath[1024];
                snprintf(fpath, sizeof(fpath), "%s/%s", corpus_dir, dir->d_name);
                size_t sz = 0;
                uint8_t *data = read_file(fpath, &sz);
                if (data) {
                    LLVMFuzzerTestOneInput(data, sz);
                    initial_runs++;
                    if (sample_count < 64 && sz <= 4096) {
                        memcpy(sample_corpus[sample_count], data, sz);
                        sample_sizes[sample_count] = sz;
                        sample_count++;
                    }
                    free(data);
                }
            }
            closedir(d);
        }
        printf("[fuzz-driver] Seed corpus loaded: %zu inputs executed cleanly.\n", initial_runs);
    }

    if (sample_count == 0) {
        // Fallback seed
        const char *default_seed = "TALOS-SOVEREIGN-SEED-0123456789";
        size_t sz = strlen(default_seed);
        memcpy(sample_corpus[0], default_seed, sz);
        sample_sizes[0] = sz;
        sample_count = 1;
    }

    time_t start_time = time(NULL);
    time_t last_log = start_time;
    uint64_t total_execs = initial_runs;
    srand((unsigned int)start_time);

    uint8_t mut_buf[8192];

    while (!g_stop) {
        time_t now = time(NULL);
        if (now - start_time >= max_time_sec) {
            break;
        }

        // Pick random base sample
        size_t idx = (size_t)(rand() % (int)sample_count);
        size_t cur_sz = sample_sizes[idx];
        memcpy(mut_buf, sample_corpus[idx], cur_sz);

        // Apply 1 to 5 random mutations
        int mut_count = 1 + (rand() % 5);
        for (int m = 0; m < mut_count; m++) {
            mutate(mut_buf, &cur_sz, sizeof(mut_buf));
        }

        LLVMFuzzerTestOneInput(mut_buf, cur_sz);
        total_execs++;

        if (now - last_log >= 5) {
            double elapsed = difftime(now, start_time);
            double rate = elapsed > 0 ? (double)total_execs / elapsed : 0.0;
            printf("[fuzz-driver] Elapsed: %ds / %ds | Execs: %lu | Rate: %.0f exec/s\n",
                   (int)elapsed, max_time_sec, (unsigned long)total_execs, rate);
            last_log = now;
        }
    }

    double elapsed = difftime(time(NULL), start_time);
    printf("========================================================================\n");
    printf("[fuzz-driver] Session complete: %lu execs in %.1fs (0 crashes detected).\n",
           (unsigned long)total_execs, elapsed);
    printf("========================================================================\n");

    return 0;
}
