#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# OSS-Fuzz build script for TALOS / LibreMobile OS security parsers.

TARGETS="fuzz_telephony_ril fuzz_nft_policy fuzz_argf2 fuzz_pif_json fuzz_battery_sysfs"

for target in $TARGETS; do
    echo "Building OSS-Fuzz target: $target..."
    $CC $CFLAGS -I. -c "fuzz/${target}.c" -o "$WORK/${target}.o"
    $CXX $CXXFLAGS "$WORK/${target}.o" -o "$OUT/${target}" $LIB_FUZZING_ENGINE

    target_name="${target#fuzz_}"

    # Package seed corpus if directory exists
    if [ -d "fuzz/corpus/${target_name}" ]; then
        zip -j -q "$OUT/${target}_seed_corpus.zip" fuzz/corpus/${target_name}/*
    fi

    # Install dictionary if exists
    if [ -f "fuzz/dict/${target_name}.dict" ]; then
        cp "fuzz/dict/${target_name}.dict" "$OUT/${target}.dict"
    fi
done
