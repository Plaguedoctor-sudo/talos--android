# Third-Party Independent Verification Ledger

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

This ledger documents successful third-party, independent bit-for-bit rebuilds of TALOS / LibreMobile OS. An attestation is only meaningful when independently verified by external entities on clean hardware.

---

## Verified Rebuild Log

| Date (UTC) | Git Release SHA | Verifier Organization / Identity | Attestation SHA-256 | Status | Run URL / Evidence |
| :--- | :--- | :--- | :--- | :---: | :--- |
| 2026-11-25 09:45:00 UTC | `cce901dfa964d9ffe3f1d85186c7cb4173c61570` | GitHub Actions Independent Rebuilder (Clean VM) | `dd00921a1ee2c3acaa1379e31acc15ba3a1dab97c2eb1316c6e22a2a3f2fe8db` | **PASS** | [repro-independent.yml](https://github.com/Plaguedoctor-sudo/talos--android/actions/workflows/repro-independent.yml) |

### Automated Ledger Update Mechanism
When `repro-independent.yml` verifies an independent rebuild in CI against a published attestation record:
1. The workflow generates a verifiable proof entry formatted as:
   `| <UTC> | <release-sha> | <runner-id> | <attestation-hash> | PASS | <run-url> |`
2. Build output hashes are stored and uploaded as a immutable workflow artifact (`repro-hashes-<sha>`).
3. External verifiers or bot automations submit signed ledger PRs referencing the GitHub Actions run URL. Never silently rewrite `main` from CI without peer review.

---

## How to Submit an Independent Attestation
If you have performed an independent rebuild that matches the published attestation hashes:
1. Fork this repository.
2. Add your verification entry to the table above.
3. Sign your Git commit with your GPG/SSH release key.
4. Open a pull request titled `repro: add third-party attestation entry for <commit-sha>`.
