# Operational Governance & Antimonopoly Architecture

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

This document operationalizes the principles set forth in [CHARTER.md](file:///home/alpha/android/CHARTER.md) into concrete, binding procedures for release management, technical leadership, financial custody, and consensus.

---

## 1. Antimonopoly Guardrails

### 1.1. Absolute Prohibition of Single-Entity Veto
**NO SINGLE-ENTITY VETO:** No single individual, commercial entity, sponsor, or hardware partner holds veto power, blocking authority, or privileged steering rights over:
1. OS releases and release schedules;
2. Inclusion or removal of software components or vendor HAL bridges;
3. Trademark policies and distribution certifications;
4. The Git source repository, documentation, or developer infrastructure.

### 1.2. Organizational Board Seat Caps
To prevent corporate capture:
- **Maximum 1 Seat Per Organization:** No single corporation, legal entity, educational institution, or investment group may hold more than one (1) voting seat on the Foundation Board.
- **Affiliation Disclosure:** Board members must disclose all employment, consulting, board memberships, equity ownership, or advisory relationships with commercial entities operating in the mobile, semiconductor, or telecommunications industries.
- **Recusal:** Members must recuse themselves from votes directly involving their employers or affiliated financial interests.

---

## 2. Ethical Funding & Commercial Prohibition Policy

TALOS is fundamentally designed as an antidote to corporate surveillance capitalism. The Foundation's financial survival must never conflict with user liberty.

### 2.1. Expressly Forbidden Revenue Streams
The Foundation, its maintainers, and official project funds are permanently barred from accepting:
- **AdTech Revenue:** Advertisements, sponsored search default slots, promoted app placements, or affiliate links within the OS;
- **Data Brokerage & Telemetry Payments:** Any consideration paid in exchange for access to device telemetry, crash analytics, user metrics, or network flow logs;
- **Behavioral Profiling Sponsorships:** Grants or agreements conditioned on embedding tracking libraries or measurement SDKs;
- **Monetized Exclusions:** Fees paid to whitelist unverified third-party trackers or bypass firewall policies.

### 2.2. Permitted Revenue Streams
The Foundation finances infrastructure, developer stipends, security audits, and legal defense strictly through:
- **Individual Community Donations:** Transparent donations via Open Collective, Liberapay, cryptocurrency, or direct foundation gifts;
- **Public Benefit Grants:** Unconditional grants from non-profit foundations (e.g., NLnet, Prototype Fund, Freedom of the Press Foundation, Sovereign Tech Fund);
- **Hardware Partner Dues:** Tiered annual membership dues from sovereign smartphone and tablet manufacturers building Treble-compliant hardware;
- **Enterprise Support & Audit Contracts:** Commercial support contracts, sovereign enterprise deployments, and hardware certification testing.

---

## 3. Cryptographic Release Signing & Multisig Quorum

To ensure that no rogue entity or compromised credential can publish a malicious operating system update, all production releases require **3-of-5 threshold multisig cryptographic authorization**.

```
                           ┌──────────────────────────┐
                           │ Reproducible Build Root  │
                           │  (`make reproducible`)   │
                           └────────────┬─────────────┘
                                        │
                         [ Bit-for-Bit Verified Match ]
                                        │
                                        ▼
                           ┌──────────────────────────┐
                           │ Attestation JSON Record  │
                           │ (`repro/attestation.json`)│
                           └────────────┬─────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼               ▼
   Keyholder 1     Keyholder 2     Keyholder 3     Keyholder 4     Keyholder 5
  (Security Lead)  (Telephony Lead)(Argus Lead)   (Board Member)  (Community Rep)
        │               │               │               │               │
        └───────┬───────┴───────┬───────┴───────────────┴───────────────┘
                │               │
                ▼               ▼
      [ Threshold Met: Minimum 3 of 5 Signatures Collected ]
                                │
                                ▼
                   ┌──────────────────────────┐
                   │ Signed Release Artifact  │
                   │ (SHA256SUMS.txt.sig)     │
                   └──────────────────────────┘
```

### 3.1. Threshold Rules
1. **Quorum:** Releases are considered officially sanctioned only when verified and signed by at least three (3) of the five (5) designated Foundation keyholders.
2. **Keyholder Diversity:** No two keyholders may be employed by or affiliated with the same commercial entity.
3. **Air-Gapped Custody:** Release signing keys must be held on hardware security modules (YubiKey / Nitrokey / Ledger) or air-gapped workstations.
4. **Attestation Cross-Reference:** Signatures are attached directly to the reproducible build attestation record generated by `make reproducible` and audited via [`repro/verify-attestation.py`](file:///home/alpha/android/repro/verify-attestation.py).

---

## 4. Irrevocable Licensing Covenant

1. **Permitted Inbound Licenses:** All inbound contributions must be licensed under OSI/FSF-approved open-source licenses:
   - GNU General Public License v3.0 or later (`GPL-3.0-or-later`) for system daemons, controllers, kernel adaptations, and security rules;
   - Apache License 2.0 (`Apache-2.0`) or MIT License (`MIT`) for shared libraries, IPC definitions, and client bridge headers.
2. **No Proprietary Relicensing:** The Foundation does not accept Contributor License Agreements (CLAs) that transfer copyright ownership or grant relicensing rights. All contributions are accepted under the Developer Certificate of Origin (DCO 1.1) with licenses running directly from contributor to the public.
3. **Permanent Open Source Guarantee:** Even in the event of foundation dissolution, bankruptcy, or asset transfer, the code remains irrevocably free software.

---

## 5. Technical Steering Council (TSC)

The Technical Steering Council is responsible for technical roadmaps, architecture, subsystem coordination, and RFC approvals.

### 5.1. Composition
- The TSC consists of all active subsystem maintainers listed in [MAINTAINERS.md](file:///home/alpha/android/MAINTAINERS.md).
- The TSC elects a Technical Chair annually to facilitate meetings and maintain RFC agendas.

### 5.2. Decision Hierarchy
1. **Lazy Consensus:** Regular pull requests require approval from the designated subsystem maintainer. If un-reviewed for 72 hours, other maintainers may review and merge.
2. **Technical Disputes:** Contested architectural changes or cross-subsystem dependencies require a formal Request for Comments (RFC) open for community review for at least fourteen (14) days.
3. **Final Resolution:** If maintainers cannot agree after the RFC period, a 2/3 majority vote of the full TSC resolves the dispute.
