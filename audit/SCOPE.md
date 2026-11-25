# ARGUS Cryptographic Trust Spine — Third-Party Audit Scope

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Document Version:** 1.0.0  
> **Status:** Pre-Audit Preparation  
> **Target Subsystem:** ARGUS Sovereign Cryptographic Custody & Trust Spine  
> **Repository:** `/home/alpha/android`  
> **Companion Documents:** [THREAT-MODEL.md](file:///home/alpha/android/audit/THREAT-MODEL.md) | [RFP.md](file:///home/alpha/android/audit/RFP.md) | [SECURITY-AUDIT.md](file:///home/alpha/android/SECURITY-AUDIT.md)

---

## 1. Executive Summary

This document specifies the exact in-scope and out-of-scope codebase boundaries for the forthcoming independent cryptographic audit of the **ARGUS Trust Spine**. ARGUS is the mathematical root-of-custody engine for TALOS / LibreMobile OS, responsible for immutable event recording, forward-secure epoch commitments, evidence vaults, duress protection, and forensic verification.

---

## 2. In-Scope Components & Exact File Ranges

Auditors must evaluate the implementation for correctness, side-channel resilience, memory safety, collision resistance, and adherence to specified cryptographic invariants across the following exact targets:

| Focus Area | File Path | Line Range | Core Architectural Functions & Invariants |
| :--- | :--- | :--- | :--- |
| **Merkle Arity-4 Tree** | [`argus/verify/record.py`](file:///home/alpha/android/argus/verify/record.py) | [L116–L172](file:///home/alpha/android/argus/verify/record.py#L116-L172) | Quad-tree BLAKE3 hashing (`_node`), depth bounding (`_depth`), root derivation (`merkle_root`), sibling path generation (`merkle_path`), and logarithmic verification walk (`walk`). |
| **ARGF/2 Binary Ledger** | [`argus/argf2/ledger.py`](file:///home/alpha/android/argus/argf2/ledger.py) | [L21–L260](file:///home/alpha/android/argus/argf2/ledger.py#L21-L260) | Segment lifecycle, header/footer validation (`SEGH`/`SEGF`), torn-write recovery, fsync degradation flags, and crash consistency. |
| **Tag Commit & Rollover**| [`argus/argf2/writer.py`](file:///home/alpha/android/argus/argf2/writer.py) | [L28–L168](file:///home/alpha/android/argus/argf2/writer.py#L28-L168) | Key derivation (`derive_tag_key`), field serialization (`TagField`), forward-secret epoch transitions, and cross-epoch equality bridges (`Bridge`). |
| **Duress Authentication** | [`argus/duress.py`](file:///home/alpha/android/argus/duress.py) | [L64–L333](file:///home/alpha/android/argus/duress.py#L64-L333) | PBKDF2-HMAC-SHA256 password hashing, constant-time dual evaluation (`compare_digest`), decoy database routing, and plausibility scoring. |
| **Dead Man's Switch** | [`argus/deadman.py`](file:///home/alpha/android/argus/deadman.py) | [L36–L159](file:///home/alpha/android/argus/deadman.py#L36-L159) | Heartbeat cadence tracking, offline timeout evaluation, false-positive protection bounds, and emergency escalation / panic isolation triggering. |
| **Evidence Vault** | [`argus/vault.py`](file:///home/alpha/android/argus/vault.py) | [L28–L223](file:///home/alpha/android/argus/vault.py#L28-L223) | Content-addressed storage, dual SHA256/BLAKE3 hashing, append-only immutable custody digest chain (`custody_digest`), and proof generation. |
| **9-Phase Verifier** | [`argus/verify/verify.py`](file:///home/alpha/android/argus/verify/verify.py) | [L18–L527](file:///home/alpha/android/argus/verify/verify.py#L18-L527) | Complete 9-phase audit pipeline: header validation, segment chaining, Merkle leaf proofs, tag digest binding, and strict exit grading. |

---

## 3. Out-of-Scope Components

The following subsystems are explicitly **out of scope** for the cryptographic audit:

1. **User Interface (UI) Layer**:
   - Web shell interface (`dist/`, `server.js`, `build.js`).
   - Wayland touch onscreen keyboard (`mobile/osk/`).
2. **Android Compatibility Container (Waydroid)**:
   - LXC runtime orchestration (`mobile/waydroid/`).
   - Binary translation bridge (`lrd-arm-bridge`).
3. **Hardware Adaptation Trees**:
   - Device trees and manifest overlays (`mobile/adaptation/`).
   - Kernel device tree source files (DTS).
4. **Third-Party Upstream Packages**:
   - Upstream Linux kernel source, Wayland Cage compositor, and hostapd/dnsmasq daemons.

---

## 4. Primary Invariant Checkpoints for Auditors

Auditors are requested to independently assert and attempt to violate the following mathematical properties:

1. **Merkle Arity-4 Completeness & Soundness**:
   - Every leaf index $i \in [0, N-1]$ possesses a verifiable proof $(sibs, dirs)$ such that $walk(sibs, dirs, leaf_i) = Root$.
   - Any single-bit mutation in any leaf payload or padding breaks verification.
   - Proof size is strictly bounded by $3 \times \lceil \log_4(N) \rceil$ 32-byte digests.
2. **Crash-Resilient Fail-Closed Epoch Rollover**:
   - Any simulated process termination, power cut, or disk torn write during epoch transition yields either a valid pre-transition state or a valid post-transition state; corrupt or half-transitioned segments must fail closed.
3. **Dead Man's Switch False-Positive Bound**:
   - A device disconnected from the network must never execute a destructive wipe if $elapsed \le timeout$. Destructive offline action must strictly require both timer breach and explicit policy authorization (`allow_offline_wipe == true`).
4. **Duress Deniability & Plausibility Gate**:
   - Duress mode enrollment must reject decoys with plausibility scores below the configured threshold, preventing trivial detection by forensic examiners. Authentication must execute in constant time regardless of credential validity.

---

## 5. Audit Commissioning Preconditions

Prior to commissioning external cryptographic audit activities, the repository must satisfy the following automated quality and integrity gates:

1. **Test Coverage Floor**:
   - Every in-scope file listed in Section 2 must maintain a strictly enforced line coverage floor of at least **70%**.
   - Core cryptographic focus components (`argus/vault.py`, `argus/argf2/`, `argus/duress.py`, `argus/deadman.py`, and `argus/verify/`) must meet or exceed **85%** line coverage.
   - Coverage verification is enforced via `make audit-prep`, which evaluates the test suite against `audit/SCOPE.md` boundaries and halts with a non-zero exit code if any target falls below 70%.
2. **Deterministic Artifact Verification**:
   - Test vectors generated in `audit/test-vectors/` must validate without defect across all 9 verification phases.
   - Verified snapshot coverage metrics are tracked in `audit/coverage-report.txt`.

