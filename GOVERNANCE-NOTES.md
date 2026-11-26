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
- See `2026-11-26T15:27:41Z` entry for the next bypass in this sequence.

---

### 2026-11-26T15:27:41Z — PR #2 merged via admin bypass

PR #2 "docs: governance log for PR #1 + Task 9 C.0–C.3 gates", 2 commits (`1de0ab0`, `79457c6` on PR branch; rebased onto `main` as `426c3f5`, `e43bbba`), merged via repository-admin bypass at `2026-11-26T15:27:41Z` onto `main` as `e43bbba` (`e43bbbaccf149b51f58151e3c49092d38445c6b9`). Reason: `C.0` (second write-access reviewer) remains unmet; the bypass path is required until it is. This is the second recorded bypass. The bootstrap loop terminates when `C.0` completes.

- **CI Checks Verified Green Prior to Merge:**
  - `cross-runner-assert`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45849071801/job/140010852537
  - `build-and-verify (ubuntu-22.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45849071801/job/140010325040
  - `build-and-verify (ubuntu-24.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45849071801/job/140010324416
  - `key-guard`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45849072179/job/140010325558
  - `repro-independent`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45849071756/job/140010324292
- **Direct Governance Record Push:** This record commit itself was pushed directly to `main` via repository-admin bypass at `2026-11-26T15:30:35Z`, not via PR (single-file governance record).
- See `2026-11-26T15:54:29Z` entry for the next bypass in this sequence.

---

### 2026-11-26T15:54:29Z — PR #3 merged via admin bypass

PR #3 "fix(repro): Docker-based build instructions; remove broken flake", 1 commit (`2c32149` on PR branch; rebased onto `main` as `5a9ff03`), merged via repository-admin bypass at `2026-11-26T15:54:29Z` onto `main` as `5a9ff03` (`5a9ff03a7b9f4188ce7ab38663524f58846c8b4c`). Reason: `C.0` (second write-access reviewer) remains unmet; the bypass path is required until it is. This is the third recorded bypass.

Scope: `C.1` (`repro/README.md` Docker-based instructions) and `C.3` (removed broken `flake.nix`/`flake.lock` from `5384ebca`, which shipped with a synthetic `narHash` and a nonexistent `nixpkgs` commit).

- **CI Checks Verified Green Prior to Merge:**
  - `cross-runner-assert`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45853366085/job/140025808679
  - `build-and-verify (ubuntu-22.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45853366085/job/140025241388
  - `build-and-verify (ubuntu-24.04)`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45853366085/job/140025241952
  - `key-guard`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45853365667/job/140025240271
  - `repro-independent`: https://github.com/Plaguedoctor-sudo/talos--android/actions/runs/45853365686/job/140025240079
- **Direct Governance Record Push:** This bypass was pushed directly to `main` via repository-admin bypass at `2026-11-26T15:57:30Z` (single-file governance record; no PR warranted). The bootstrap loop terminates when `C.0` completes.
