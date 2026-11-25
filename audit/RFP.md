# Request for Proposal (RFP): ARGUS Cryptographic Audit

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Document ID:** RFP-TALOS-ARGUS-2026-01  
> **Status:** Open for Bids  
> **Target Subsystem:** ARGUS Sovereign Cryptographic Custody Engine  
> **Codebase:** [github.com/Plaguedoctor-sudo/talos--android](https://github.com/Plaguedoctor-sudo/talos--android)  
> **Operator Action:** `TODO(operator): select auditor and finalize contract dates`

---

## 1. Objective & Scope of Work

The TALOS / LibreMobile OS Foundation invites reputable cryptographic and systems security auditing firms to submit formal proposals to conduct an independent security review and formal invariant audit of the **ARGUS Trust Spine**.

The full technical scope, file ranges, and protected invariants are defined in **[audit/SCOPE.md](file:///home/alpha/android/audit/SCOPE.md)** and **[audit/THREAT-MODEL.md](file:///home/alpha/android/audit/THREAT-MODEL.md)**.

---

## 2. Required Auditor Qualifications

Proposals will only be accepted from firms or independent security researchers meeting the following minimum criteria:

1. **Demonstrated Cryptographic Expertise**:
   - Proven track record in auditing Merkle tree structures, BLAKE3/SHA-256 primitives, zero-knowledge/tag commitments, and forward-secure state machines.
   - Publicly available audit reports for major open-source or defense-grade security protocols (e.g. Signal, WireGuard, Tor, Matrix, or Linux kernel cryptographic subsystems).
2. **Systems & Kernel Proficiency**:
   - Experience auditing Python 3 cryptographic runtimes, SQLite transactional integrity, and low-level Linux IPC / systemd daemon boundaries.
3. **Formal Verification / Property-Based Testing Literacy**:
   - Ability to review and extend Hypothesis property tests and static test vector suites.
4. **Independence & Governance Compliance**:
   - Firm must adhere to the TALOS Sovereign Commons Charter ([CHARTER.md](file:///home/alpha/android/CHARTER.md)); firms with commercial affiliations to surveillance-advertising vendors or proprietary data brokers are disqualified.

---

## 3. Required Deliverables

The engagement requires four formal deliverables:

1. **Initial Audit Report (Draft)**:
   - Detailed inventory of findings categorized using the rubric in [audit/findings/TEMPLATE.md](file:///home/alpha/android/audit/findings/TEMPLATE.md).
   - Clear proof-of-concept (PoC) exploit scripts or property test counterexamples for each identified vulnerability.
   - Specific, actionable architectural remediation recommendations.
2. **Remediation & Triage Consultation**:
   - Synchronous technical review sessions with TALOS maintainers to discuss triage and verify proposed security patches.
3. **Retest & Verification Phase**:
   - Formal verification of all merged bug fixes and patches to ensure vulnerabilities are fully resolved without regressions.
4. **Final Public Audit Report**:
   - Unredacted (or responsibly coordinated) public report published directly in the TALOS repository under an open CC-BY or OSI/FSF license.

---

## 4. Timeline & Engagement Milestones

| Milestone | Target Duration | Description |
| :--- | :--- | :--- |
| **RFP Submission Deadline** | 3 weeks | Submission of firm credentials, team bios, and fixed-price bids. |
| **Auditor Selection** | 1 week | Foundation review and operator sign-off (`TODO(operator)`). |
| **Code Freeze & Pre-Audit Briefing** | 3 days | Tagging baseline commit hash and technical kickoff briefing. |
| **Active Audit Period** | 3–4 weeks | Deep-dive code review, fuzzing, and property invariant evaluation. |
| **Remediation Window** | 2 weeks | Project maintainers patch reported findings. |
| **Retest & Final Sign-Off** | 1 week | Auditor verifies fixes and delivers final signed report. |

---

## 5. Budget Band & Financial Terms

- **Budget Band:** `TODO(operator): $25,000 – $65,000 USD (grant-funded sovereign commons allocation)`.
- **Payment Structure:**
  - 30% upon formal contract execution and kickoff.
  - 40% upon delivery of the initial draft audit report.
  - 30% upon completion of the retest and delivery of the final public report.
- **Surveillance Prohibition:** Consistent with [CHARTER.md](file:///home/alpha/android/CHARTER.md), all funding is strictly sourced from non-profit grants and community donations; no funding tied to adtech or telemetry is permitted.

---

## 6. Coordinated Vulnerability Disclosure Terms

- The audit will follow a strict **90-day Coordinated Vulnerability Disclosure (CVD)** timeline.
- Critical findings that could lead to remote code execution or cryptographic compromise of real storage keys will be triaged under an expedited private security advisory process (`GHSA`).
- The final audit report will be committed to `audit/reports/` and signed with the foundation release keys.
