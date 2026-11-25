# Charter of the TALOS / LibreMobile Sovereign Commons Foundation

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

## 1. Preamble & Mission Statement

The TALOS / LibreMobile OS Project is organized as a sovereign digital commons dedicated to liberating mobile telecommunications and personal computing from monopolistic corporate surveillance, planned obsolescence, and proprietary hardware lock-in.

### Foundational Sovereign Aims
The Foundation is constitutionally bound to uphold the following six core aims:
1. **Sovereign Un-Googled Computing:** Eradicate all mandatory corporate telemetry, proprietary tracking runtimes (Google Mobile Services / GMS), and persistent device surveillance beacons from the base operating system.
2. **Zero-Bloat Native Efficiency:** Reject multi-gigabyte Java frameworks (Zygote, SystemServer, and the ART runtime) in favor of deterministic, native C daemons that idle at **under 30 MB combined RAM**, maximizing battery longevity and responsiveness.
3. **Defense-Grade Anti-Surveillance:** Enforce privacy-by-design at every layer: dynamic Wi-Fi and BLE MAC address rotation, deny-by-default `nftables` egress filtering, DNS-over-TLS (port 853), Tor SOCKS5h routing, zero-trust synthetic feeds for unauthorized sensor requests, and instantaneous network panic isolation.
4. **ARGUS Mathematical Custody & Trust Spine:** Commit all system state changes, capability grants, and alibi timestamps to an immutable, BLAKE3-hashed, arity-4 Merkle ledger (`ARGF/2`) with epoch-bound `tag_commit` equality proofs that reveal zero plaintext metadata.
5. **Universal Portability via Project Treble:** Maintain strict generic system partition (`system.img`) compatibility to run across ARM64 smartphones and tablets while respecting manufacturer Board Support Packages (BSPs) and Generic Kernel Images (GKI).
6. **Isolated Android Containerization:** Run optional third-party Android applications strictly inside an unprivileged LXC sandbox (Waydroid) with GPU acceleration and Play Integrity spoofing (`pif.json`), ensuring zero host compromise.

---

## 2. Legal Form & Organization

1. **Non-Profit Structure:** The project is organized as a non-profit foundation operating exclusively for scientific, educational, and public benefit purposes.
2. **Jurisdiction:** 
   <!-- TODO(operator): Specify legal incorporation jurisdiction (e.g., Swiss Verein under Art. 60ff ZGB, Delaware 501(c)(3) Non-Profit, or Estonian Non-profit Association MTÜ). -->
   `TODO(operator): Jurisdictional domicile to be designated by the Foundation Board upon formal incorporation.`
3. **Asset Protection:** All intellectual property, domains, cryptographic signing keys, and repository assets are held in trust by the Foundation for the perpetual benefit of the sovereign commons.

---

## 3. Membership Classes

The Foundation recognizes five distinct membership classes:

1. **User Members:** Individuals who install and use TALOS on their personal devices. User members participate in community forums, test releases, and elect one community representative to the Foundation Board.
2. **Contributor Members:** Individuals with documented non-trivial contributions (code, documentation, translation, hardware testing, or issue triaging) within the prior 12 months. Contributor members hold voting rights on technical proposals.
3. **Maintainer Members:** Subsystem maintainers entrusted with direct commit access and technical direction of specific modules. Maintainers collectively form the Technical Steering Council (TSC).
4. **Organizational Members:** Academic institutions, non-profit privacy bodies, civil liberties NGOs, and research labs that support the Foundation through infrastructure, research, or grants.
5. **Hardware Partner Members:** Commercial device vendors and hardware manufacturers that engineer, validate, and ship TALOS-compatible sovereign devices adhering strictly to the Project Treble specification.

---

## 4. Board Composition & Antimonopoly Guardrails

The Foundation Board of Directors oversees legal compliance, financial integrity, trademark defense, and infrastructure sustainability.

### Antimonopoly Board Rules
1. **Board Size:** The Board consists of 5 to 7 voting members.
2. **Organizational Seat Cap:** **No single corporation, organization, entity, or conglomerate may hold more than one (1) voting seat on the Board.** Affiliated entities (parent companies, subsidiaries, or majority-owned entities) are counted as a single entity.
3. **Independence Quorum:** At least 50% of the voting Board seats must be held by independent contributors or non-commercial community representatives.

---

## 5. Constitutional Clauses

### 5.1. NO SINGLE-ENTITY VETO CLAUSE
**Under no circumstances shall any individual, company, sponsor, hardware vendor, or donor hold blocking power, exclusive rights, or veto authority over the TALOS codebase, roadmap, releases, or trademark.** 
Any attempt to condition funding, hardware access, or sponsorship on veto authority or proprietary control is null and void *ab initio*.

### 5.2. SURVEILLANCE & TELEMETRY FUNDING PROHIBITION CLAUSE
The Foundation is constitutionally prohibited from accepting any funding, revenue, grant, or sponsorship derived from or conditioned upon:
1. **Targeted Advertising (AdTech)** or commercial tracking;
2. **Data Brokerage** or user telemetry collection;
3. **Behavioral Profiling** or surveillance monetization;
4. **In-OS Telemetry Quotas** or commercial analytics collection.

**Permitted Funding Sources:**
- Voluntary individual and community donations;
- Unconditional public benefit grants from research foundations and privacy funds;
- Transparent annual dues from Hardware Partner Members;
- Enterprise support, audit, and custom integration contracts.

### 5.3. IRREVOCABLE FREE SOFTWARE COVENANT
All code, documentation, specifications, and hardware adaptation scripts contributed to TALOS must be licensed under OSI- and FSF-approved licenses (GPL-3.0-or-later for daemons and scripts; Apache-2.0 / MIT for libraries and bridge headers). **The Foundation has no legal power to relicense the codebase to a proprietary or closed-source license.**

---

## 6. Decision Process & Consensus Model

1. **Lazy Consensus (Default):** Technical and operational proposals are deemed accepted if no maintainer objects within seventy-two (72) hours of public posting.
2. **Escalation & Review:** If a maintainer formally dissents, the proposal enters active review. Maintainers must attempt to reach rough consensus through documented technical trade-offs.
3. **Council Supermajority:** If rough consensus cannot be reached, the issue is decided by a two-thirds (2/3) supermajority vote of the Technical Steering Council.
4. **Board Supermajority:** Non-technical governance disputes, trademark actions, and legal matters are decided by a two-thirds (2/3) supermajority of the Board.

---

## 7. Amendment Process

Amendments to this Charter require:
1. A mandatory thirty (30) day public community review and comment period;
2. A three-fourths (3/4) supermajority vote of the Technical Steering Council;
3. A three-fourths (3/4) supermajority vote of the Foundation Board of Directors;
4. Under no condition may an amendment weaken or repeal Section 5.1 (No Single-Entity Veto), Section 5.2 (Funding Prohibition), or Section 5.3 (Irrevocable Free Software Covenant).
