# ARGUS Cryptographic Trust Spine — Threat Model

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Document Version:** 1.0.0  
> **Status:** Active Security Specification  
> **Target Subsystem:** ARGUS Trust Spine  
> **Companion Documents:** [SCOPE.md](file:///home/alpha/android/audit/SCOPE.md) | [RFP.md](file:///home/alpha/android/audit/RFP.md)

---

## 1. Protected Assets

The ARGUS trust spine is designed to defend four primary classes of high-value assets:

1. **Master Cryptographic Keys & Keyrings**:
   - Device identity secret keys (Ed25519).
   - Tag derivation master secrets (`master_key`).
   - LUKS2 storage encryption keys and TPM 2.0 / KeyMint enrollment bindings.
2. **Ledger Integrity & Non-Repudiation**:
   - Append-only binary ledger history (`ARGF/2`).
   - Tamper-evident BLAKE3 Merkle roots and cross-epoch `tag_commit` equality bridges.
   - Absence and presence proofs for system audit records.
3. **Plausible Deniability & Duress Secrecy**:
   - Secrecy of the existence of real databases when operating under duress credentials.
   - Plausibility of decoy environments against forensic disk analysis.
   - Resistance to timing side-channels during credential authentication.
4. **Physical Custody Proofs & Alibis**:
   - Content-addressed evidence chains in the vault.
   - Tamper-evident velocity timestamps and multiboot continuity chains.

---

## 2. Adversary Classes & Capabilities

| Adversary Profile | Capabilities & Attack Vectors | Security Objective |
| :--- | :--- | :--- |
| **ADV-1: Physical Device Seizure** | Possesses physical hardware; can read raw eMMC/UFS flash chips; can freeze RAM; can power-cycle or interrupt I/O during state transitions. | Prevent plaintext extraction; guarantee fail-closed recovery on power cuts; preserve duress deniability. |
| **ADV-2: Remote Network Interceptor** | Controls network transit (ISP/cellular base station); injects packets, blocks ports, attempts MitM on TLS/DoT/Tor endpoints. | Prevent false deadman triggering; prevent DNS leaks; prevent replay of signed ledger segments. |
| **ADV-3: Compelled Disclosure / Duress** | Legally or physically coerces the operator to surrender unlock PINs or decryption passwords under immediate threat. | Provide convincing decoy workspace; emit silent duress alert; prevent discovery of real volume presence. |
| **ADV-4: Malicious Sandboxed App** | Runs unprivileged code in container (Waydroid) or mobile userspace; probes local sockets (`/run/libredroid`), attempts timing attacks. | Enforce constant-time auth; prevent socket impersonation; enforce strict deny-by-default nftables. |
| **ADV-5: Supply Chain & Build Compromise** | Attempts to introduce backdoors, non-deterministic compiler outputs, or corrupted dependencies into upstream releases. | Neutralized by bit-for-bit reproducible builds, machine-verifiable attestations, and 3-of-5 multisig release gates. |

---

## 3. Component Invariants

### 3.1. Merkle Arity-4 Tree (`argus/verify/record.py`)
- **INV-M1 (Inclusion Completeness):** For any leaf $L$ at index $i$ in a tree of size $N$, `walk(merkle_path(leaves, i), L) == merkle_root(leaves)`.
- **INV-M2 (Collision Resistance):** Given computationally bounded adversaries, no two distinct leaf sequences $A \ne B$ yield $merkle\_root(A) = merkle\_root(B)$.
- **INV-M3 (Tamper Sensitivity):** Flipping any single bit in any leaf digest $L_i$ causes $walk(path_i, L_i') \ne Root$ with probability $1 - 2^{-256}$.
- **INV-M4 (Path Bound):** Sibling path length is strictly $3 \times \lceil \log_4(N) \rceil$ 32-byte elements.

### 3.2. Epoch Transitions & `tag_commit` (`argus/argf2/writer.py`)
- **INV-E1 (Forward Secrecy):** Compromise of epoch $k+1$ tag keys does not permit derivation of epoch $k$ tag keys or historical plaintext field values.
- **INV-E2 (Bridge Equivalence):** If `tag_a` in epoch $k$ and `tag_b` in epoch $k+1$ reference the same underlying identifier, the verifier accepts them if and only if a valid signed `Bridge` record links them.
- **INV-E3 (Fail-Closed Rollover):** A crash, kill signal, or power cut at any intermediate write step during epoch rollover must leave the segment readable as the previous epoch or cleanly unfinalized; partial or unverified segments must be rejected by `argus-verify`.

### 3.3. Duress & Decoy System (`argus/duress.py`)
- **INV-D1 (Constant-Time Verification):** Password evaluation time $T(P_{real}) \approx T(P_{duress}) \approx T(P_{invalid})$; the timing delta between real and duress authentication must be undetectable over local IPC.
- **INV-D2 (Deniability Isolation):** Under duress authentication, the system must never open, read, stat, or leak paths referencing `real_db_path`.
- **INV-D3 (Plausibility Lower Bound):** A decoy environment must achieve a plausibility score $S_{decoy} \ge S_{min}$ based on realistic database size, historical timestamps, and activity logs before enrollment is permitted.

### 3.4. Dead Man's Switch (`argus/deadman.py`)
- **INV-H1 (Zero False Positives within Grace):** While $elapsed \le timeout\_seconds$, the switch status is strictly `ACTIVE` or `WARNING`, and destructive escalation is impossible.
- **INV-H2 (Offline Policy Guard):** Destructive panic wiping is forbidden when offline unless the operator has explicitly armed `allow_offline_wipe = true`.
