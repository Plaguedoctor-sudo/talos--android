# Security Policy & Coordinated Vulnerability Disclosure

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

The TALOS / LibreMobile OS project takes security and cryptographic integrity seriously. We welcome reports from security researchers, reverse engineers, and the open-source community to identify vulnerabilities and harden our sovereign mobile platform.

---

## 1. Vulnerability Reporting

To report a suspected security vulnerability, send an encrypted email to our security response team:

- **Security Contact**: `security@talos-project.org`
- **PGP Encryption**: `TODO(operator): provision PGP key fingerprint & public key block for security@talos-project.org`

Please include in your report:
1. Affected component(s) and version/commit hash.
2. Step-by-step reproduction instructions or a minimal Proof-of-Concept (PoC).
3. Assessment of vulnerability impact (e.g., local privilege escalation, remote code execution, cryptographic ledger corruption).
4. Any relevant crash logs, ASAN/UBSAN stack traces, or fuzzing inputs.

We will acknowledge receipt within **48 hours** and provide regular status updates during investigation and remediation.

---

## 2. Coordinated Disclosure Window

We follow a strict **90-day Coordinated Vulnerability Disclosure (CVD)** timeline:
- **0–48 hours**: Initial triage, researcher acknowledgement, severity grading.
- **Day 1–30**: Root cause verification, patch development in private security branches.
- **Day 30–60**: Backport testing, verification against property suites and fuzz harnesses.
- **Day 60–90**: Coordinated release tagging, CVE assignment, advisory publication.
- **Critical Under Active Exploitation**: If active exploitation in the wild is confirmed, remediation and disclosure may be accelerated to **7 days**.

Researchers agree not to disclose vulnerability details publicly prior to the expiration of the 90-day window or mutually agreed advisory publication.

**Emergency Key Compromise Disclosure**: Any secret key material committed to this repository MUST be disclosed within 24 hours at the security contact; do not push history rewrites without coordination.

---

## 3. Safe Harbor Clause

We believe that independent security research is essential to a sovereign mobile ecosystem. We operate under an explicit **Safe Harbor policy**:

- **Authorization**: If you conduct research and report findings in accordance with this policy, we consider your activities authorized, good-faith security research.
- **No Legal Action**: We will not initiate legal action against you under anti-hacking or anti-circumvention statutes (such as the US Computer Fraud and Abuse Act (CFAA), Digital Millennium Copyright Act (DMCA) Section 1201, or international equivalents).
- **Scope & Boundaries**: Safe harbor applies as long as you:
  - Do not intentionally disrupt production services or violate user privacy.
  - Do not access, modify, or exfiltrate data belonging to other users.
  - Comply with the 90-day coordinated disclosure policy.
  - Do not execute physical extortion or social engineering attacks.

---

## 4. Scope

### In-Scope
The following components maintained within the TALOS / LibreMobile OS repository are strictly **in-scope**:

1. **Native Daemons (`mobile/*/lrd-*`)**:
   - `mobile/telephony/` (`lrd-telephonyd`, `lrd-telephony`, AT/RIL parser, SMS PDU decoder)
   - `mobile/firewall/` (`lrd-firewalld`, `lrd-firewall`, netfilter policy manager)
   - `mobile/wifi/` (`lrd-wifid`, `lrd-wifi`, wpa_supplicant control socket parser)
   - `mobile/bluetooth/` (`lrd-bluetoothd`, `lrd-bluetooth`, BlueZ control manager)
   - `mobile/sensors/` (`lrd-sensord`, IIO sensor bus manager)
   - `mobile/power/` (`lrd-wakelockd`, `lrd-battery-guardian.sh`, sysfs thermal/charge manager)
2. **ARGUS Trust Architecture (`argus/*`)**:
   - Binary ledger and ARGF/2 binary serialization (`argus/verify/record.py`, `fuzz_argf2.c`)
   - Merkle arity-4 audit trees and inclusion proofs
   - Tag commit epoch transitions and boundary verifiers
   - Plausible deniability duress engine (`argus/duress.py`)
   - Hardware-backed deadman switch (`argus/deadman.py`)
   - Master key isolation and sealed vault operations (`argus/vault.py`)
3. **Security Infrastructure (`security/*`)**:
   - Outbound egress policy enforcement and TOML schema validation
   - Open attestation RATS/EAT verification engine (`attestation/rats-verifier/`)
   - Antimonopoly app distribution layer and cryptographic index verification (`store/`)

### Out-of-Scope
- Upstream Waydroid container internals and AOSP framework bugs (please report to upstream LineageOS / Waydroid).
- Third-party binary vendor firmware blobs (modem, GPU, Wi-Fi baseband).
- Social engineering, phishing, physical theft of unlocked devices, or volumetric denial-of-service (DDoS).

---

## 5. Bug Bounty Program & Reward Tiers

We recognize and reward security researchers who help protect TALOS users. Rewards are awarded based on impact:

| Severity | Reward Band (USD) | Example Scenarios |
| :--- | :--- | :--- |
| **Critical** | **$5,000 – $10,000** | Remote unauthenticated RCE (e.g. telephony SMS PDU parser), cryptographic break of ARGF/2 ledger integrity, master key extraction from vault under normal boot. |
| **High** | **$2,000 – $5,000** | Local privilege escalation from unprivileged app to daemon/root, egress firewall bypass allowing undeclared network exfiltration, duress deniability break. |
| **Medium** | **$500 – $2,000** | Denial of Service against critical system daemons (`lrd-telephonyd`, `lrd-firewalld`), battery charge limiter bypass causing thermal degradation, unauthorized sensor access. |
| **Low** | **$100 – $500** | Minor information leaks, non-security logic flaws, local denial-of-service requiring root privileges. |

*Note*: `TODO(operator): configure bug bounty funding source and escrow account (e.g., Open Collective, GitHub Sponsors, or community security fund)`.

---

## 6. Compromised Keys & Incident Disclosure

### Incident Report: INC-2026-001 (Store Index Signing Key Exposure)

- **Affected Key:** Store Index Ed25519 Private Signing Key (`store/keys/fdroid-signing.sec`)
- **Compromised Fingerprint (SHA-256):** `d990d9b364f780f4350030968fde559414f0b275e353eb47ebb794fc672ee391`
- **Initial Exposure Commit:** `82ce129`

#### Incident Timeline
1. **2026-11-25 12:15 UTC:** During initial test generation of the F-Droid store index, `store/keys/fdroid-signing.sec` was inadvertently committed to Git.
2. **2026-11-25 12:59 UTC:** Defect identified during security and integrity audit.
3. **2026-11-25 13:05 UTC:** Remediation applied:
   - Secret key purged from the working directory and index via `git rm`.
   - Release key pin revoked in `store/keys/fingerprint.txt` to `UNPINNED`.
   - History rewrite script prepared (`scripts/rewrite-history-for-key-removal.sh`) using `git filter-repo`.
   - Pre-commit key guard enacted (`scripts/pre-commit-key-guard.sh`) blocking secret key extensions.
   - Pinned public key verification fails closed in `store/verify-index.sh` if release key is unpinned.
4. **2026-11-25 17:30:55 UTC:** History rewritten at 2026-11-25 17:30:55 UTC. All forks, clones, and caches created before this timestamp may contain the compromised key and MUST be considered unsafe. Fork owners are asked to delete and re-fork.

#### Residual exposure after history rewrite
GitHub forks, CI caches, and third-party mirrors created before the rewrite may still retain the compromised key material in unpruned Git loose objects or cached refs. For this reason, history rewrite is necessary but not sufficient: the only safe remediation is permanent key rotation and untrusting the compromised fingerprint (as enforced by `store/POLICY.md` and `store/verify-index.sh`). Any store index signed with fingerprint `d990d9b364f780f4350030968fde559414f0b275e353eb47ebb794fc672ee391` is permanently rejected.

#### Client-Side Impact & Advisory
- No TALOS production client should ever have trusted this key.
- If any downstream client or test system pinned fingerprint `d990d9b364f780f4350030968fde559414f0b275e353eb47ebb794fc672ee391`, malicious index poisoning and package spoofing could occur.
- **Action:** Any client with this key pinned must unpin it immediately. The store index will ship unsigned until the operator provisions an offline release key outside version control. Reference [store/keys/COMPROMISED.md](file:///home/alpha/android/store/keys/COMPROMISED.md) and [store/POLICY.md](file:///home/alpha/android/store/POLICY.md).
