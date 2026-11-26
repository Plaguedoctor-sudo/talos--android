# Governance Notes & Deviation Log

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Purpose:** Chronological log of operational governance actions that deviate from [`GOVERNANCE.md`](GOVERNANCE.md) rules (such as bootstrap-phase repository-admin bypass merges), maintained to preserve artifact-over-log honesty per [`CONTRIBUTING.md §4.2`](CONTRIBUTING.md#L87-L96).
>
> - **Not for security incidents:** Confidentiality, integrity, or key-compromise disclosures belong in [`SECURITY.md`](SECURITY.md).
> - **Not for standing rules:** Constitutional aims and governance policies live in [`CHARTER.md`](CHARTER.md) and [`GOVERNANCE.md`](GOVERNANCE.md).

---

## 2026-11-26 — PR #1 self-merged via admin bypass (`2026-11-26T15:08:24Z`)

- **Pull Request:** PR #1 — `chore: test hygiene + Task 9 scope + hermetic CI fix` (`chore/test-hygiene-and-task9-scope` → `main`)
- **Commits included:** 4 commits (`090d45d`, `8b2424f`, `711ca13`, `8146ee1` on PR branch; rebased onto `main` as `b83265f`, `a4038eb`, `406e066`, `adcd4f8`)
- **Merge Method:** Rebase and merge (via repository-admin bypass)
- **Merge Timestamp (UTC):** `2026-11-26T15:08:24Z`
- **New `main` HEAD:** `adcd4f81f3a3e32e33e2d782b0e06f33a07c68e2` (`adcd4f8`)
- **CI Checks Verified Green Prior to Merge:**
  - `cross-runner-assert`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45842879827/job/139989461008
  - `build-and-verify (ubuntu-22.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45842879827/job/139988882699
  - `build-and-verify (ubuntu-24.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45842879827/job/139988883041
  - `key-guard`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45842879649/job/139988882924
  - `repro-independent`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45842879664/job/139988882446
- **Reason for Bypass:** The `Protect main` ruleset requires `approvals=1` from a write-access reviewer other than the PR author, and at the time of merge the project had only one write-access maintainer account.

### Findings Log (`2026-11-26`)

Cross-runner reproducibility defect found and fixed. The `cross-runner-assert` job in [`.github/workflows/repro.yml`](.github/workflows/repro.yml) failed for the first time, revealing that daemons/images/tarballs diverge between `ubuntu-22.04` and `ubuntu-24.04` due to host-toolchain differences (`gcc` 11 vs. 13, `glibc` 2.35 vs. 2.39, `e2fsprogs` 1.46 vs. 1.47). Prior bit-for-bit reproducible claims were based on same-runner double builds (`scripts/repro-attest.sh`), which prove determinism but not cross-environment reproducibility. Resolution (commit `8146ee1`, rebased onto `main` as `adcd4f8`): the build was made hermetic via a pinned Debian bookworm container (`repro/Dockerfile`, digest `sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e`). This upgrades the reproducibility claim from same-host determinism to cross-environment hermeticity.

### Required Remediation

- **Gate `C.0`:** Onboard a second write-access reviewer and merge at least one PR under normal `Protect main` rules (without admin bypass) before treating governance rules as satisfied.
- Until `C.0` is complete, any bootstrap-phase merge using the repository-admin bypass (including follow-up PRs recording prior bypasses) must be logged in this file with the same structure.
