<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-4.0
-->

# TALOS Sovereign Distribution & App Store Policy

> **Document Status:** Authoritative Repository Inclusion Policy  
> **Target Subsystem:** `store/` & Sovereign Package Index  
> **Governing Charter:** [CHARTER.md](file:///home/alpha/android/CHARTER.md) & [GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md)  
> **Scoring Engine:** `store/privacy-score.py` (Algorithm Version: `1.0.0`)

---

## 1. Guiding Principles & Antimonopoly Mandate

The TALOS Application Distribution Layer is an antimonopoly, sovereign software ecosystem. Unlike proprietary app stores (Google Play and Apple App Store), TALOS enforces:
1. **Zero Gatekeeper Tax:** No revenue commissions, developer subscription fees, or pay-to-play discovery algorithms.
2. **Deterministic Transparency:** Applications are indexed alongside machine-computed **Privacy Scores (0–100)** and reproducible build attestations.
3. **Defense Against Surveillance Capitalism:** Zero tolerance for third-party commercial trackers, behavioral analytics SDKs, and undeclared telemetry.
4. **Declarative Network Boundaries:** Every application must declare its egress requirements via a strict template matchable to `security/egress/policy/*.toml`.

---

## 2. Mandatory Inclusion Criteria

To be indexed and distributed through the official TALOS store repository, every package must satisfy five non-negotiable criteria:

### 2.1 Free and Open Source Licensing (FOSS)
- All application source code, assets, and libraries must be released under an **OSI-approved** or **FSF-recognized Free Software license** (e.g., GPL-3.0-or-later, AGPL-3.0-or-later, Apache-2.0, MIT, MPL-2.0, BSD-3-Clause).
- Proprietary binary blobs, non-free dependencies, and proprietary compiler plugins are strictly prohibited.

### 2.2 Bit-for-Bit Reproducible Builds
- Package builds must be reproducible from tagged public source commits.
- Third-party rebuilders must be able to reproduce bit-identical APK/package hashes using standard build recipes (e.g., `repro-build.sh` or F-Droid reproducible build metadata).
- **Temporary Waiver Clause:** If an application is FOSS but currently lacks a reproducible build recipe, maintainers may issue a temporary waiver signed by $\ge 2$ Foundation maintainers with a dated remediation milestone (maximum duration: 180 days).

### 2.3 Strict Tracker Transparency & Commercial Prohibition
- **Zero Advertising / Profiling SDKs:** Inclusion of advertising networks (e.g., Google AdMob, Unity Ads, Facebook Audience Network, AppLovin) or behavioral surveillance SDKs (e.g., AppsFlyer, Adjust, Branch, Kochava) results in **immediate rejection or ejection**.
- **Vendored Dataset Matching:** Applications are statically analyzed against the vendored Exodus Privacy signature database ([store/data/trackers.json](file:///home/alpha/android/store/data/trackers.json)).
- **Telemetry Disclosure:** Privacy-respecting crash reporters (e.g., self-hosted Sentry or ACRA) must:
  1. Be explicitly declared in package metadata.
  2. Be strictly **opt-in** (disabled by default).
  3. Strip all hardware identifiers, MAC addresses, and persistent device tokens.

### 2.4 Mandatory Egress Policy Declaration
- Every application must submit a corresponding declarative egress policy matching `security/egress/policy/<package_id>.toml`.
- The template must specify:
  - `mode`: `blocked` (no network access permitted), `isolated_lan`, `vpn_only`, `tor_strict`, or `tunnel_only`.
  - `allowed_destinations`: List of explicit FQDNs or CIDR ranges.
  - `dns_policy`: `enforce_dot` (DNS-over-TLS port 853) or `tor_dns`.
  - `anti_leak_killswitch`: Must be enabled for network-active applications.

### 2.5 Zero Google Play Services Dependency
- Applications must execute fully without requiring proprietary Google Mobile Services (GMS), Google Play Store, or proprietary SafetyNet / Play Integrity attestation.
- Applications requesting integrity attestation must support open RATS tokens (RFC 9334 / RFC 9711) or local sandbox operation.

---

## 3. Privacy Scoring Model (0–100)

Every application is scored deterministically by [store/privacy-score.py](file:///home/alpha/android/store/privacy-score.py) using the following weighted metric:

| Metric Component | Maximum Weight | Scoring Criteria & Deductions |
|:---|:---:|:---|
| **Tracker Absence** | **35 pts** | **35 pts** for 0 trackers detected. Deducts **25 pts** per commercial ad/profiling tracker, **15 pts** per analytics tracker, and **10 pts** per crash reporter. |
| **Permission Restraint** | **20 pts** | **20 pts** for minimal permissions. Deducts **4 pts** per intrusive permission (`ACCESS_FINE_LOCATION`, `CAMERA`, `RECORD_AUDIO`, `READ_CONTACTS`, `READ_SMS`, `READ_PHONE_STATE`). |
| **Build Reproducibility** | **20 pts** | **20 pts** for verified bit-for-bit reproducible builds; **5 pts** for documented waiver; **0 pts** for unverified builds. |
| **Egress Policy Alignment** | **15 pts** | **15 pts** for offline (`blocked`) mode; **12 pts** for `tor_strict` / `vpn_only` matching declared policy; **0 pts** for undeclared egress. |
| **Maintenance Recency** | **10 pts** | **10 pts** if updated within 90 days; **7 pts** within 365 days; **2 pts** within 2 years; **0 pts** if unmaintained (>3 years). |

### Grade Classification
- **A+ (95 – 100):** Exemplary sovereign application: 0 trackers, reproducible, strict egress sandbox, minimal permissions.
- **A (85 – 94):** Fully compliant sovereign app with standard permissions and verified provenance.
- **B (70 – 84):** FOSS compliant; minor deductions for non-reproducible build waiver or broader permission set.
- **C (55 – 69):** Warning tier; contains self-hosted opt-in diagnostic reporter or broad egress scope.
- **F (< 55):** Ineligible for repository distribution.

---

## 4. Signing, Indexing, and Curation

- **Signed Manifests:** Repository metadata is published to `store/index/index.json` accompanied by a detached Ed25519 signature (`index.json.sig`).
- **Pinned Key:** Verifiers authenticate index signatures against the pinned Foundation signing key stored in `store/keys/fdroid-signing.pub` and validated against `store/keys/fingerprint.txt`.
- **Emergency Revocation:** If a security regression or undeclared tracker is discovered post-release, the package is immediately removed from the index and an append-only ARGUS audit revocation event is logged.

---

## 5. Signing Key Lifecycle

To prevent catastrophic repository poisoning, private release keys are governed by strict operational protocols:

1. **Air-Gapped Offline Generation:**
   - Private signing keys must NEVER be generated on internet-connected build servers or committed to any Git repository.
   - Operators generate release keys on offline, air-gapped workstations using `scripts/provision-store-key.sh` or standard OpenSSL/cryptography CLI outside the repository tree (e.g. `~/.config/talos/store-signing.sec`).
   - Only the public key (`fdroid-signing.pub`) and SHA-256 fingerprint (`fingerprint.txt`) are committed to version control.
2. **Hardware Security Module (HSM) Recommendation:**
   - Production index signing should be performed via FIPS 140-2 Level 3 HSMs or smartcards (e.g., YubiKey 5 FIPS, Nitrokey Pro/Storage) utilizing PKCS#11 tokens where secret keys cannot be extracted.
3. **Annual Rotation Cadence:**
   - Signing keys must be rotated at least once every 365 days.
   - Rotations must be signed with both old and new keys for a 30-day grace transition period.
4. **Emergency Revocation Procedure:**
   - If a private signing key is suspected of compromise, the operator must:
     1. Immediately mark `store/keys/fingerprint.txt` as `UNPINNED — operator must provision release key per store/POLICY.md`.
     2. Document the compromised fingerprint in `store/keys/COMPROMISED.md` and publish a security advisory per `SECURITY.md`.
     3. Trigger `scripts/rewrite-history-for-key-removal.sh` if private material was accidentally committed.
     4. Notify the security response team within 24 hours at `security@talos-project.org`.

`TODO(operator): Provision primary production Ed25519 repository release keys into ~/.config/talos/store-signing.sec and pin public key in store/keys/fingerprint.txt.`
