# Task 9 Scope Proposal (Pending Operator Selection)

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

> **Status:** Proposal Only — Awaiting Operator Selection (Do Not Implement Until Approved)  
> **Base Branch State (`main`):** `adcd4f81f3a3e32e33e2d782b0e06f33a07c68e2` (`adcd4f8`, PR #1 merged `2026-11-26T15:08:24Z`)  
> **Proposal Branch `HEAD`:** PR #2 (`docs/governance-notes-and-task9-c0-c3`, after `1de0ab0`)  
> **Captured UTC Timestamp:** `2026-11-26T15:12:00Z`

---

## 1. Context & Trigger Verification State

All three STEP 0 prerequisite triggers are verified as repository and GitHub artifacts rather than narrative claims:

| Trigger Item | Status | Verified Artifact Evidence |
| :--- | :--- | :--- |
| **Store Key Rotation & Pinning** | **COMPLETE** | Rotated Ed25519 public key in [`store/keys/fdroid-signing.pub`](../store/keys/fdroid-signing.pub#L1) decodes to SHA-256 `28482f20bfce30989494247c5532a8273daddc9a5871348a7b2f5ada54847742`, matching [`store/keys/fingerprint.txt`](../store/keys/fingerprint.txt#L1) (`39ff284`). |
| **Branch Protection (`main`)** | **COMPLETE** | GitHub Ruleset `Protect main` active since `2026-11-26T13:32:58Z` (recorded in [`SECURITY.md`](../SECURITY.md#L117-L121), `7c9270b`) requiring PRs (`approvals=1`), linear history, deletion restriction, force-push block, and status checks `key-guard` + `repro-independent` (`Repository admin` bypass). |
| **Signed Release Attestation** | **COMPLETE** | Detached Ed25519 signature [`repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json.sig`](../repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json.sig#L1) verifies against [`store/keys/fdroid-signing.pub`](../store/keys/fdroid-signing.pub#L1) over [`repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json`](../repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json) (`54f18db`). |

Additionally, PR #1 (rebased onto `main` at `adcd4f8` on `2026-11-26T15:08:24Z`; recorded in [`GOVERNANCE-NOTES.md`](../GOVERNANCE-NOTES.md)) resolved test hygiene and CI hermeticity gaps discovered during STEP 0 resumption:
- `b83265f` (PR #1 `090d45d`): Refactored `tests/test_store_scoring.py` (`test_unsigned_graceful_degradation` and `test_signature_verification_gate`) to test isolated `tmp_path` fixtures instead of live `store/keys/fingerprint.txt`.
- `a4038eb` (PR #1 `8b2424f`): Hardened `Makefile` `verify-strict` to require exact exit code `2`, updated `scripts/key-guard.sh` to report offending blob paths on stderr, and added `tests/test_key_guard_negative.py` (`make check` pytest count increased from 44 to 47).
- `adcd4f8` (PR #1 `8146ee1`): Routed `.github/workflows/repro.yml` through pinned Debian bookworm container [`repro/Dockerfile`](../repro/Dockerfile) (`sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e`), turning `cross-runner-assert` green across `ubuntu-22.04` and `ubuntu-24.04`.

---

## 2. Open Repository Items (Observed State)

The following open items were pulled directly from current tracked files and local build logs:

### 2.1. Cryptographic Audit Procurement (`audit/RFP.md`, `SECURITY-AUDIT.md`, `audit/coverage-report.txt`)
- `audit/RFP.md:12`: `TODO(operator): select auditor and finalize contract dates` (mirrors `SECURITY-AUDIT.md:19`).
- `audit/RFP.md:59-66`: Engagement timeline spans 3 weeks for RFP submission, 1 week for `Auditor Selection` (`audit/RFP.md:62`, `TODO(operator)`), 3 days code freeze/briefing, 3–4 weeks active audit, 2 weeks remediation, and 1 week retest/sign-off.
- `audit/RFP.md:72`: Budget band remains `TODO(operator): $25,000 – $65,000 USD (grant-funded sovereign commons allocation)`.
- `audit/coverage-report.txt:28-69`: Focus modules meet the `audit/SCOPE.md:78-79` floor (`argus/vault.py` 95%, `argus/argf2/ledger.py` 93%, `argus/argf2/writer.py` 100%, `argus/duress.py` 88%, `argus/deadman.py` 99%, `argus/verify/verify.py` 85%), while total `argus` coverage is 65% across 3,106 statements because out-of-scope or auxiliary modules remain at 0% (`argus/alibi.py:31`, `argus/compartments.py:47`, `argus/isolation.py:53`, `argus/sentinel.py:56`, `argus/tor.py:58`, `argus/watcher.py:67`) or low coverage (`argus/argf2/producers/audit_netlink.py` 29% at `L38`, `argus/chronology.py` 31% at `L46`, `argus/db.py` 34% at `L49`).

### 2.2. Hardware RATS Provisioning (`attestation/rats-verifier/`)
- `attestation/rats-verifier/README.md:29`: `TODO(operator): Provision hardware-backed Endorsement Key (EK) certificates and deploy production TPM 2.0 Attestation Keys (AK) signed by OEM/foundation CAs.`
- `attestation/rats-verifier/tpm.py:88-89`: Same EK/AK provisioning TODO on `verify_quote_signature`; current verifier vectors in `attestation/rats-verifier/vectors/` are synthetic test fixtures (`valid_eat_token.json`, `pinned_aks.json`, `golden_rim.json`), not hardware TPM 2.0 quotes.
- `attestation/rats-verifier/verifier.py:65-66`: `TODO(operator): Configure enterprise root of trust and populate golden_rim from reproducible build attestation hashes (repro/attestation-<git-sha>.json).`

### 2.3. Hardware Matrix & Firmware Provenance (`hardware/matrix.yaml`)
- `hardware/matrix.yaml:113-141`: Roadmap target `Purism` `Librem 5 v2 (RISC-V)` (`talos_support_level: "Roadmap"`) has unresolved TODOs for SoC (`L114`), modular open-firmware modem (`L121`), baseband DSP/COTS M.2 module (`L127-130`), and OpenSBI/U-Boot SPL bootloader payload (`L133-136`), with `verified: false` (`L131`, `L137`).
- `hardware/matrix.yaml:228-233`: Tier C `Google` `Pixel 6` entry `Titan M2 (Dauntless) Security Core Firmware` has `source: "TODO(operator): Verify Google OpenTitan derivation vs proprietary build"` (`L230`), empty `source_url: ""` (`L231`), and `verified: false` (`L232`).
- Across `hardware/matrix.yaml:29-318`, every proprietary firmware blob entry across Tier B and Tier C devices still carries `source_url: ""` and `verified: false`.

### 2.4. Independent Rebuild Verification Ledger (`repro/THIRD-PARTY-VERIFICATIONS.md`)
- `repro/THIRD-PARTY-VERIFICATIONS.md:14-18`: Only two ledger entries exist:
  - `L16`: `UNSIGNED SELF-CHECK` (`self (github-actions@ubuntu-24.04)`) for `cce901dfa964d9ffe3f1d85186c7cb4173c61570`.
  - `L17`: `SIGNED SELF-CHECK` (`project-signer@offline-workstation`) for `cce901dfa964d9ffe3f1d85186c7cb4173c61570`.
- There are **zero `INDEPENDENT VERIFICATION` rows** in the table (`L14-18`).
- `repro/THIRD-PARTY-VERIFICATIONS.md:25`: Narrative note is also stale — it still claims `there are zero SIGNED SELF-CHECKS` and `The store signing key is UNPINNED`, despite `L17` and `store/keys/fingerprint.txt:1` now being pinned and signed.

### 2.5. Cellular Telephony Matrix Verification (`mobile/telephony/SUPPORT.md`, `mobile/telephony/support.yaml`)
- `mobile/telephony/SUPPORT.md:16-24` (backed by `mobile/telephony/support.yaml:4-115`):
  - Native Linux phones (`PINE64 PinePhone` `L16`, `PinePhone Pro` `L17`, `Purism Librem 5` `L18`) and `Volla Phone 22` (`L19`) keep `MMS` and `VoLTE` at `⚠️ Experimental` and `VoNR` / `eSIM` at `✖ Unsupported`.
  - `Google Pixel 6` (`L20`) and `Fairphone 4 5G` (`L21`) mark `VoLTE` and `eSIM` as `✔ Supported` and `VoNR` as `⚠️ Experimental`, while `Xiaomi POCO F3` (`L22`) keeps `MMS` and `VoNR` at `⚠️ Experimental` and `eSIM` at `✖ Unsupported`.
  - `Purism Librem 5 v2 (RISC-V)` (`L23`) lists Data, Voice, SMS, MMS, eSIM, and Emergency as `❓ Untested`.
- `mobile/telephony/SUPPORT.md:29-33, 38-45`: Highlights carrier-certification gaps blocking promotion from `⚠️ Experimental` — IMS/VoLTE carrier whitelisting & `mbn`/`apns-conf.xml` profiles (`L29`, `L39`), absence of a native Linux SGP.22 LPA for eSIM (`L31`, `L42`), `mmsd-tng` MMS routing (`L32`), and unverified VoLTE E911/112 emergency fallback where 2G/3G networks are retired (`L45`).

### 2.6. Continuous Fuzzing Corpus & Coverage (`fuzz/`, `out/fuzz/`, `Makefile`)
- Five C harnesses exist (`fuzz/fuzz_argf2.c` 102L, `fuzz/fuzz_battery_sysfs.c` 145L, `fuzz/fuzz_nft_policy.c` 160L, `fuzz/fuzz_pif_json.c` 246L, `fuzz/fuzz_telephony_ril.c` 195L), wired for OSS-Fuzz (`fuzz/oss-fuzz/project.yaml:3-13`, `fuzz/oss-fuzz/build.sh:7-25`).
- Local seed corpora remain minimal (1–3 files per harness):
  - `fuzz/corpus/argf2/`: 1 seed (`seed1_header.bin`).
  - `fuzz/corpus/pif_json/`: 1 seed (`seed1_pif.json`).
  - `fuzz/corpus/nft_policy/`: 2 seeds (`seed1_fdroid.toml`, `seed2_calculator.toml`).
  - `fuzz/corpus/telephony_ril/`: 2 seeds (`seed1_pdu.txt`, `seed2_ril.txt`).
  - `fuzz/corpus/battery_sysfs/`: 3 seeds (`seed1_limit.txt`, `seed2_status.txt`, `seed3_uevent.txt`).
- `out/fuzz/*_smoke.log:1-16`: All five harnesses passed 60s smoke runs with 0 crashes (`fuzz_argf2`: 201,287,811 execs; `fuzz_telephony_ril`: 26,540,068 execs; `fuzz_battery_sysfs`: 26,338,689 execs; `fuzz_nft_policy`: 17,854,449 execs; `fuzz_pif_json`: 5,139,278 execs).
- **Below OSS-Fuzz steady state across all 5 targets:** `clang` is not installed in the build environment (`Makefile:106-120` falls back to GCC + ASAN/UBSAN + `fuzz/standalone_driver.c:51-88`, which performs unguided PRNG mutation without libFuzzer edge-coverage feedback). Consequently, none of the 5 harnesses has generated a coverage-guided corpus, `llvm-cov` / `lcov` branch-coverage baseline, or ClusterFuzz integration run, and `fuzz_pif_json` (`5.14M` execs, 1 seed for a 246-line recursive parser) and `fuzz_argf2` (1 seed, simplified standalone struct parser with dummy XOR sink at `fuzz/fuzz_argf2.c:82-86`) lag furthest behind realistic parser coverage.

---

## 3. Candidate Task 9 Objectives

The six constitutional sovereign aims referenced below are defined in [`CHARTER.md`](../CHARTER.md#L13-L19):
1. **Aim 1:** Sovereign Un-Googled Computing
2. **Aim 2:** Zero-Bloat Native Efficiency
3. **Aim 3:** Defense-Grade Anti-Surveillance
4. **Aim 4:** ARGUS Mathematical Custody & Trust Spine
5. **Aim 5:** Universal Portability via Project Treble
6. **Aim 6:** Isolated Android Containerization

| Candidate | Objective | Measurable "Done" | Estimated Effort | Dependencies | Sovereign Aims Advanced |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | **Commission the ARGUS Audit** (execute [`audit/RFP.md`](../audit/RFP.md)) | Auditor selected and contracted (`audit/RFP.md:12` & `SECURITY-AUDIT.md:19` updated with firm name, baseline tag/SHA, and dates); initial draft findings triaged under [`audit/findings/TEMPLATE.md`](../audit/findings/TEMPLATE.md); fixes + retest verification vectors committed; signed final public report stored in `audit/reports/`. | **High** (6–8 weeks calendar; vendor coordination + remediation cycle) | Grant/foundation funding allocation (`$25k–$65k` per `audit/RFP.md:72`), auditor RFP bids, code freeze tag on `main`. | **Aim 4** (ARGUS Mathematical Custody & Trust Spine); indirectly **Aim 3** (audit of egress/duress controls). |
| **B** | **Provision RATS Attestation (EK/AK) on a Tier B Reference Device** | Non-synthetic TPM 2.0/hardware EK certificate chain + CA-signed AK provisioned outside repo; `golden_rim` populated from signed [`repro/attestation-<sha>.json`](../repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json); real device EAT token + quote artifact committed and verified `AFFIRMED` by `python3 -m attestation.rats_verifier.cli verify`. | **Medium–High** (1–2 weeks engineering + hardware access) | Physical Tier B hardware with TPM 2.0 / hardware root-of-trust (or OpenTitan/secure element), OEM/foundation CA key setup, `ATTESTATION.md` RIM mapping. | **Aim 1** (replaces Play Integrity trust model), **Aim 4** (cryptographic integrity attestation), **Aim 6** (unblocks Waydroid RATS HAL broker). |
| **C** | **Onboard First Independent Verifier & Record First `INDEPENDENT VERIFICATION`** | Complete hard gates **`C.0`–`C.3`** below, then an external third party (distinct identity/hardware/infra from project maintainers) independently clones `main`, rebuilds via the pinned Docker path (`make reproducible-docker` + containerized `make reproducible`), verifies SHA-256 outputs match the re-signed hermetic attestation, and submits a peer-reviewed PR (merged **without** admin bypass) adding the first `INDEPENDENT VERIFICATION` row to [`repro/THIRD-PARTY-VERIFICATIONS.md`](../repro/THIRD-PARTY-VERIFICATIONS.md#L14) and fixing stale status text at `L25`. | **Low–Medium** (3–7 days including `C.0`–`C.3` + external run) | `C.0` (second reviewer + non-bypass PR proof), `C.1` (`repro/README.md` Docker docs), `C.2` (re-generated & signed Docker attestation), `C.3` (`flake.nix`/`flake.lock` resolved). **C.0 must complete before any `INDEPENDENT VERIFICATION` submission is merged.** | **Aim 1** & **Aim 4** (proves un-Googled binaries match auditable source without trusting maintainer infrastructure); supports **Aim 5** (verifiable Treble/GSI artifacts). |
| **D** | **Complete Telephony Matrix Verification on a Carrier-Certified Device** | Physical run against a Tier B/C carrier-certified reference device (e.g., Pixel 6 or Fairphone 4 5G) capturing schema-validated `lrd-telephonyd --caps` output (`mobile/telephony/schema.json`), documented carrier IMS/VoLTE + SMS + E911 test evidence logs, and updates to [`mobile/telephony/SUPPORT.md`](../mobile/telephony/SUPPORT.md) & [`support.yaml`](../mobile/telephony/support.yaml) backed by `make telephony-matrix-check`. | **Medium** (1–2 weeks with physical handset + active SIM/carrier) | Physical reference handset, active carrier SIMs, real modem interface (`AT`/`QMI`/Halium RIL) rather than simulated fallback. | **Aim 2** (native C `lrd-telephonyd` efficiency) & **Aim 5** (verified portable hardware behavior). |
| **E** | **Harden Fuzz Coverage to OSS-Fuzz Acceptance Criteria** | Install Clang + libFuzzer/SanitizerCoverage in CI/local env; expand each of the 5 corpora from 1–3 seeds to diverse multi-branch corpora (especially `fuzz_pif_json` and `fuzz_argf2`); link harnesses to real parser code where feasible; achieve documented coverage baseline via `llvm-cov` / `fuzz/oss-fuzz/build.sh` inside OSS-Fuzz build image with zero ASAN/UBSAN/OOM/timeout findings. | **Medium** (3–6 days engineering + CI runtime) | Clang/libFuzzer toolchain (`fuzz.yml` / OSS-Fuzz Docker base image); no external hardware or legal contracts required. | **Aim 2** (hardens native C daemons), **Aim 3** (telephony/egress/battery parser safety), **Aim 4** (ARGF/2 parser safety), **Aim 6** (`pif.json` parser safety). |

### Candidate C Prerequisites & Hard Gates (`C.0` – `C.3`)

- **`C.0` — Onboard second write-access reviewer (GATE):**
  Before the first `INDEPENDENT VERIFICATION` row can be merged, the project must have a second write-access reviewer so external verification PRs undergo real peer review rather than repository-admin bypass.
  - **Acceptance:** A second GitHub account with write access, recorded in [`MAINTAINERS.md`](../MAINTAINERS.md) with their PGP or SSH key fingerprint, and **one PR merged under the `Protect main` ruleset WITHOUT admin bypass**.
  - **Production Signing Ceremony Remediation:** Bootstrap-phase attestations signed from the maintainer workstation are functional for bootstrap only, not production-grade. Establish a production signing ceremony — HSM or air-gapped machine, at least two witnesses, recorded procedure in [`GOVERNANCE.md`](../GOVERNANCE.md).
- **`C.1` — Update [`repro/README.md`](../repro/README.md) to point at Docker-based build:**
  Independent verifiers must run `make reproducible-docker` (building [`repro/Dockerfile`](../repro/Dockerfile) and executing `make reproducible` inside the pinned container, matching [`.github/workflows/repro.yml`](../.github/workflows/repro.yml)) so their hashes match the hermetic build. Old host-toolchain instructions must be removed or clearly marked deprecated.
- **`C.2` — Regenerate and re-sign the release attestation:**
  The historical attestation at [`repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json`](../repro/attestation-cce901dfa964d9ffe3f1d85186c7cb4173c61570.json) was produced by the `ubuntu-24.04` host toolchain (`gcc 13.3.0`) and does not match the new hermetic Debian bookworm Docker build (`adcd4f8`). Generate a new attestation via the `make reproducible-docker` container workflow at the post-fix `HEAD`, sign it with the rotated offline key (`28482f20…`), commit the `.sig`, and add a `SIGNED SELF-CHECK` row. Without this, no `INDEPENDENT VERIFICATION` can succeed.
- **`C.3` — Resolve broken [`flake.nix`](../flake.nix) / [`flake.lock`](../flake.lock):**
  [`flake.lock`](../flake.lock) references a nonexistent `nixpkgs` commit (`205a52458428d015e123c75d869a05ced640b8a5`) and a synthetic `narHash`. Either fix both in a follow-up commit, or delete [`flake.nix`](../flake.nix) and [`flake.lock`](../flake.lock) and note in [`repro/README.md`](../repro/README.md) that Docker is the supported hermetic path. A broken flake is worse than no flake.
- **Candidate C Future Cleanup Items (Post-C.2, Out of C.2 Scope):**
  - **Cleanup:** Remove pre-rewrite attestations from [`repro/`](../repro) (`2ae350f`, `36901f`, `cce901d`). They are unreachable and serve no purpose but clutter the attestation directory.
  - **Cleanup:** Refine `find_release` ordering in [`.github/workflows/repro-independent.yml`](../.github/workflows/repro-independent.yml) before adding a second reachable attestation (currently stops at the first lexicographical reachable `repro/attestation-*.json` when no release tag exists).

---

## 4. Recommended Task 9 Objective

**Recommendation: Candidate C — Onboard First Independent Verifier & Record First `INDEPENDENT VERIFICATION` Row** (optionally paired with **A** if the operator wants to launch external RFP solicitation in parallel).

All prerequisite engineering for supply-chain verifiability is now in place on `main` — deterministic dual builds (`scripts/repro-attest.sh`), offline Ed25519 key rotation and pinning (`39ff284`), the first signed release attestation (`54f18db`), PR/check branch protection (`7c9270b`), and cross-runner hermetic CI (`adcd4f8`) — yet [`repro/THIRD-PARTY-VERIFICATIONS.md`](../repro/THIRD-PARTY-VERIFICATIONS.md#L14-L25) still contains zero `INDEPENDENT VERIFICATION` rows, and PR #1 required admin bypass because only one write-access maintainer exists. Completing `C.0`–`C.3` and onboarding one genuinely independent external verifier establishes real peer-reviewed merge capability (`C.0`), aligns documentation and signed attestations with the hermetic Docker build (`C.1`–`C.2`), removes the misleading Nix flake trap (`C.3`), and converts the existing `SIGNED SELF-CHECK` into the repository's first third-party trust signal without hardware procurement or RFP contract delays. **C.0, C.1, C.2, C.3 must complete before the first INDEPENDENT VERIFICATION submission can be merged.**

---

## 5. Explicit Out-of-Scope for Task 9

To prevent scope creep during Task 9 execution, the following are explicitly **out of scope** unless separately authorized by the operator:
1. **Unselected candidates:** Implementing B, D, or E (or A if C alone is chosen) inside Task 9 PRs.
2. **Gate or branch-protection weakening:** Using `Repository admin` bypass for routine PRs, relaxing `verify-strict` exact exit-code checks, or adding private-key/source exclusions to `.keyguard-allow`.
3. **Premature Play Integrity purge:** Deleting `mobile/waydroid/pif.json` or breaking transitional fallback behavior ahead of the `PIF_ROADMAP.md` / [`ROADMAP.md`](../ROADMAP.md#L100-L110) 2027 sunset schedule.
4. **ARGF/2 wire format changes:** Altering the binary `ARGF/2` record header/footer layout (`argus/argf2/`) before external audit baseline freeze.
5. **Simulated evidence presented as hardware/external proof:** Recording CI self-runs as `INDEPENDENT VERIFICATION`, synthetic EAT vectors as hardware TPM quotes, or mocked `lrd-telephonyd` output as carrier-certified hardware evidence.

---

## 6. Acceptance Gates for Task 9 (Artifact-Over-Log Principle)

Consistent with [`CONTRIBUTING.md §4.2`](../CONTRIBUTING.md#L87-L96) and Tasks 1–8, **every Task 9 deliverable must be gated on inspectable artifacts (cryptographic signatures, binary/file SHA-256 digests, schema-validated outputs, and regression test vectors) — never commit messages, diff text, or prose assertions.**

### Baseline Repository Gates (Mandatory for Any Task 9 PR)
- `make check` exits `0` (`test-trust`, `test-mobile`, `test-guards`, and `verify-strict` enforcing exact exit `2`).
- `make verify-strict` exits `0` (and exits non-zero if `VERIFY_STRICT_CMD` returns anything other than `2`).
- `make store-score-test` exits `0` (using fixture-isolated tests, independent of live `store/keys/fingerprint.txt`).
- `make key-guard` exits `0` (`scripts/key-guard.sh` confirms zero prohibited paths and zero PEM private key blobs in all reachable Git blobs).
- `make reuse-lint` exits `0` (100% REUSE/SPDX attribution across all files).

### Candidate-Specific Artifact Gates
- **If Candidate C is selected:**
  - Detached signature / GPG-signed PR commit from an external verifier key distinct from project maintainer keys.
  - Verifiable rebuild output hashes matching `per_artifact_sha256` inside signed `repro/attestation-<sha>.json` via `repro/verify-attestation.py` (exit `0`) plus linked external CI/build evidence URL.
  - [`repro/THIRD-PARTY-VERIFICATIONS.md`](../repro/THIRD-PARTY-VERIFICATIONS.md) passes an automated consistency check confirming at least one `INDEPENDENT VERIFICATION` row references an existing signed attestation file whose `.sig` verifies against [`store/keys/fdroid-signing.pub`](../store/keys/fdroid-signing.pub).
- **If Candidate A is selected:**
  - Executed auditor selection fields in [`audit/RFP.md`](../audit/RFP.md) / [`SECURITY-AUDIT.md`](../SECURITY-AUDIT.md), pinned baseline commit tag, and signed public audit report blob in `audit/reports/` accompanied by reproducible PoC regression tests in `tests/`.
- **If Candidate B is selected:**
  - Hardware EK cert chain + CA-signed AK public metadata + captured device EAT token artifact passing `python3 -m attestation.rats_verifier.cli verify` with `verdict == "AFFIRMED"` against a `golden_rim` derived from signed `repro/attestation-<sha>.json` hashes.
- **If Candidate D is selected:**
  - Captured runtime `lrd-telephonyd --caps` JSON artifact passing `mobile/telephony/schema.json` validation alongside carrier test logs; `make telephony-matrix-check` exits `0`.
- **If Candidate E is selected:**
  - `fuzz/oss-fuzz/build.sh` compiles cleanly under Clang + libFuzzer (`-fsanitize=fuzzer,address,undefined`), committed seed corpora + `llvm-cov` coverage report demonstrate non-trivial branch coverage across all 5 targets, and `make fuzz-smoke` completes with 0 crashes.
