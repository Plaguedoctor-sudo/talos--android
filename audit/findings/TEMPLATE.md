# Security Finding Template & Severity Rubric

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Document Version:** 1.0.0  
> **Audience:** External Security Auditors & Maintainers

---

## 1. Severity Classification Rubric

Audit findings are graded across both standard **CVSS v3.1 Base Scores** and project-specific **TALOS Sovereign Impact Ratings**:

| Severity | CVSS v3.1 | TALOS Sovereign Project Impact Criteria |
| :--- | :---: | :--- |
| **CRITICAL** | 9.0 – 10.0 | Direct extraction of device master keys; forgeability of arbitrary Merkle proofs without detection; silent bypass of duress deniability leading to disclosure of real databases; unauthenticated remote code execution. |
| **HIGH** | 7.0 – 8.9 | Broken forward secrecy across epoch boundaries; timing side-channel revealing real vs. duress credentials over local IPC; unintended trigger of deadman wipe resulting in unrecoverable data loss; denial-of-service crashing the verification engine. |
| **MEDIUM** | 4.0 – 6.9 | Suboptimal entropy in tag salt generation; partial state desynchronization requiring manual operator recovery; unverified metadata fields permitted in non-critical segment headers; excessive proof size violating logarithmic bounds. |
| **LOW** | 0.1 – 3.9 | Incomplete documentation of invariant edge-cases; non-constant-time comparison in non-secret metadata; code maintainability defects in verification passes. |
| **INFORMATIONAL** | N/A | Hardening suggestions, code style recommendations, or performance optimizations that do not affect cryptographic correctness. |

---

## 2. Standard Finding Report Template

```markdown
### [FINDING-ID]: Title of the Vulnerability

- **Target Component:** `argus/<subsystem>/<file>.py` (Lines Lxx–Lyy)
- **Severity Rating:** `[CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL]`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Score: x.x)
- **Status:** `[REPORTED | TRIAGED | PATCHED | VERIFIED]`

#### Vulnerability Description
Detailed description of the defect, why the invariant was breached, and how it impacts system confidentiality, integrity, or plausible deniability.

#### Threat Invariant Violated
Reference the violated invariant from `audit/THREAT-MODEL.md` (e.g. `INV-M3`, `INV-D1`, `INV-E3`).

#### Proof of Concept / Counterexample
Step-by-step reproduction instructions or a minimal test script / Hypothesis counterexample reproducing the failure:

```python
# Minimal reproduction script
def test_exploit_poc():
    pass
```

#### Remediation Recommendation
Concrete technical fix, including code diff or architectural changes required to restore the invariant.

#### Maintainer Triage & Resolution Note
- **Resolution Commit:** `<git-sha>`
- **Auditor Verification:** Verified on `<date>` by `<Auditor Name>`.
```
