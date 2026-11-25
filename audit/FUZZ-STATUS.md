# Continuous Fuzzing Coverage & Harness Status

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

This document tracks continuous fuzz testing harnesses, seed corpora, dictionaries, execution speeds, and parser attack surfaces for TALOS / LibreMobile OS security-critical components.

---

## 1. Fuzzing Harnesses Matrix

All harnesses implement standard libFuzzer `LLVMFuzzerTestOneInput()` entry points and compile with AddressSanitizer (ASAN) and UndefinedBehaviorSanitizer (UBSAN). When Clang is not present in build environments, harnesses automatically link against `fuzz/standalone_driver.c`.

| Harness | Target Parser Surface | Language / File | Dictionary | Seed Corpus | Baseline Exec Speed |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `fuzz_telephony_ril` | GSM 03.40 SMS PDU decoder & Hayes AT / RIL unsolicited responses | C / `fuzz/fuzz_telephony_ril.c` | `fuzz/dict/telephony_ril.dict` | `fuzz/corpus/telephony_ril/` (2 seeds) | ~419,000 exec/s |
| `fuzz_nft_policy` | TOML egress policy parser (`security/egress/policy/*.toml`) | C / `fuzz/fuzz_nft_policy.c` | `fuzz/dict/nft_policy.dict` | `fuzz/corpus/nft_policy/` (2 seeds) | ~264,000 exec/s |
| `fuzz_argf2` | 128-byte packed binary ARGF/2 segment header & tag records | C / `fuzz/fuzz_argf2.c` | `fuzz/dict/argf2.dict` | `fuzz/corpus/argf2/` (1 binary seed) | ~3,200,000 exec/s |
| `fuzz_pif_json` | Waydroid Play Integrity Fix (PIF) JSON parser | C / `fuzz/fuzz_pif_json.c` | `fuzz/dict/pif_json.dict` | `fuzz/corpus/pif_json/` (1 JSON seed) | ~85,000 exec/s |
| `fuzz_battery_sysfs` | Linux `power_supply` sysfs attributes & uevent buffers | C / `fuzz/fuzz_battery_sysfs.c` | `fuzz/dict/battery_sysfs.dict` | `fuzz/corpus/battery_sysfs/` (3 seeds) | ~432,000 exec/s |

---

## 2. Threat & Parser Model

1. **`fuzz_telephony_ril`**:
   - *Threat*: Malicious over-the-air cellular base station or rogue SIM injecting malformed SMS PDUs or unsolicited AT/RIL responses into `lrd-telephonyd`.
   - *Sanitizers*: Heap/stack buffer overflow, off-by-one semi-octet nibble shifts, UCS-2 endian overflow.
2. **`fuzz_nft_policy`**:
   - *Threat*: Malicious application attempting egress escape by crafting malformed TOML egress policy rules or buffer overflow in table/chain parsers.
   - *Sanitizers*: Array boundary violation, unescaped string bounds, invalid mode token injection.
3. **`fuzz_argf2`**:
   - *Threat*: Untrusted log record injection into immutable ARGUS audit stream.
   - *Sanitizers*: Header truncation, magic number spoofing, payload length integer overflow, malformed tag record offset loops.
4. **`fuzz_pif_json`**:
   - *Threat*: Malicious or corrupted Play Integrity profile payloads attempting memory corruption during Waydroid bootstrap.
   - *Sanitizers*: Unclosed quotation loops, deep recursion stack overflow, integer parsing errors in `FIRST_API_LEVEL`.
5. **`fuzz_battery_sysfs`**:
   - *Threat*: Malicious kernel sysfs injection or thermal attack causing battery degradation through corrupted charging threshold parsing.
   - *Sanitizers*: Out-of-range integer clamping, negative current reading overflow, newline/whitespace token parsing.

---

## 3. OSS-Fuzz Integration

Integration files for Google OSS-Fuzz are maintained in `fuzz/oss-fuzz/`:
- `fuzz/oss-fuzz/project.yaml`: Project metadata, contacts, and engine configurations.
- `fuzz/oss-fuzz/build.sh`: Multi-target libFuzzer packaging script linking `$LIB_FUZZING_ENGINE` and packaging corpus zip archives and dictionaries into `$OUT`.

---

## 4. CI & Regression Automation

- **Nightly CI**: `.github/workflows/fuzz.yml` triggers nightly fuzzing across all targets for 60 seconds each.
- **Local Verification**:
  ```bash
  make fuzz              # Compile all 5 harnesses with ASAN + UBSAN
  make fuzz-smoke        # Run 60s per target with zero crashes
  make fuzz-run TARGET=fuzz_telephony_ril DURATION=120
  ```
- **Crash Reporting**: Crashes, ASAN reports, and reproduction inputs are saved to `out/fuzz/crashes/` and uploaded as workflow artifacts.
