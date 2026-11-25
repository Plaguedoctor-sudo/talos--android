# TALOS / ARGUS Security Audit Status

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

[![Audit Status: Pre-Commission](https://img.shields.io/badge/audit%20status-pre--commission-orange.svg)](audit/RFP.md)
[![Property Tests: Verified](https://img.shields.io/badge/property%20tests-100%25%20verified-brightgreen.svg)](tests/)
[![Threat Model](https://img.shields.io/badge/threat%20model-documented-blue.svg)](audit/THREAT-MODEL.md)

---

## 1. Current Audit Status

> **Current Status:** **Audit Not Yet Commissioned**  
> **Target Subsystem:** ARGUS Sovereign Cryptographic Custody & Trust Spine  
> **Preparation Phase:** Pre-Audit Verification, Property-Based Invariant Testing, and Request for Proposal (RFP) Open  
> **Operator Action:** `TODO(operator): select auditor from qualified bidders and finalize contract dates`

TALOS / LibreMobile OS adheres to radical transparency in security claims. Ahead of commissioning a comprehensive third-party cryptographic review, the project has codified all target components, formal threat invariants, property-based verification suites, and committed test vectors directly within the repository.

---

## 2. Scope & Target Components

The forthcoming security audit focuses strictly on the mathematical core and security-critical custody layers of ARGUS:

| Subsystem | Exact Path | Scope Summary | Invariants Audited |
| :--- | :--- | :--- | :--- |
| **Merkle Arity-4 Tree** | [`argus/verify/record.py`](file:///home/alpha/android/argus/verify/record.py) | Quad-tree BLAKE3 hashing, leaf padding, inclusion path generation, and logarithmic verification walks. | Inclusion completeness, single-bit tamper sensitivity, proof size bounds. |
| **ARGF/2 Binary Ledger** | [`argus/argf2/ledger.py`](file:///home/alpha/android/argus/argf2/ledger.py) | Append-only segment structure, torn-write recovery, and crash-resilient rollover. | Fail-closed recovery, immutable segment chaining. |
| **Tag Commit & Epoch Rollover**| [`argus/argf2/writer.py`](file:///home/alpha/android/argus/argf2/writer.py) | Key derivation (`derive_tag_key`), tag field commit proofs, and cross-epoch bridges. | Forward-secure epoch rollovers, bridge equality verification. |
| **Duress Authentication** | [`argus/duress.py`](file:///home/alpha/android/argus/duress.py) | Dual PBKDF2 verification, constant-time compare, decoy database routing, and plausibility scoring. | Side-channel timing neutrality, decoy deniability, plausibility threshold gating. |
| **Dead Man's Switch** | [`argus/deadman.py`](file:///home/alpha/android/argus/deadman.py) | Offline heartbeat monitoring, false-positive protection bounds, emergency escalation. | Zero false positives during grace period, offline wipe authorization guard. |
| **Evidence Vault** | [`argus/vault.py`](file:///home/alpha/android/argus/vault.py) | Content-addressed storage, SHA-256 and BLAKE3 hashing, custody event chaining. | Immutable blob retention, hash-linked chain verification. |
| **9-Phase Verifier** | [`argus/verify/verify.py`](file:///home/alpha/android/argus/verify/verify.py) | Forensic validation engine, segment boundary integrity, and strict grading. | Soundness, zero false-negative defect detection. |

*Out-of-Scope:* Web UI shell (`dist/`, `server.js`), Waydroid LXC Android container, and hardware adaptation manifests. See **[audit/SCOPE.md](file:///home/alpha/android/audit/SCOPE.md)** for details.

---

## 3. Formal Invariants & Property-Based Verification

To ensure that the codebase is completely audit-ready, every core focus area is continuously verified using property-based testing (`hypothesis`) and static vectors:

- **Merkle Arity-4 Completeness & Tamper Resilience:** [`tests/test_argf2_properties.py`](file:///home/alpha/android/tests/test_argf2_properties.py)
- **Epoch Rollover & Crash Consistency:** [`tests/test_argf2_properties.py`](file:///home/alpha/android/tests/test_argf2_properties.py)
- **Dead Man's Switch False-Positive Bounds:** [`tests/test_deadman_properties.py`](file:///home/alpha/android/tests/test_deadman_properties.py)
- **Duress Decoy Plausibility & Timing Neutrality:** [`tests/test_duress_properties.py`](file:///home/alpha/android/tests/test_duress_properties.py)
- **Committed Static Test Vectors:** [`audit/test-vectors/`](file:///home/alpha/android/audit/test-vectors)

To run the full pre-audit property test suite and generate a coverage report locally:
```bash
make audit-prep
```

---

## 4. Auditor RFP & Bidding Instructions

Qualified cryptographic auditing firms are invited to review **[audit/RFP.md](file:///home/alpha/android/audit/RFP.md)** and submit proposals. In accordance with [CHARTER.md](file:///home/alpha/android/CHARTER.md), all audit findings will be published openly upon completion.
