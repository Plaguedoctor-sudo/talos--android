# Third-Party Independent Verification Ledger

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

This ledger documents successful third-party, independent bit-for-bit rebuilds of TALOS / LibreMobile OS. An attestation is only meaningful when independently verified by external entities on clean hardware.

---

## Verified Rebuild Log

| Date (UTC) | Git Commit SHA | Verifier Organization / Identity | Build Environment | Attestation Status | Verifier PGP / Signature |
| :--- | :--- | :--- | :--- | :---: | :--- |
| — | — | `TODO(operator): first independent rebuild pending` | — | ⏳ Pending | — |

---

## How to Submit an Independent Attestation
If you have performed an independent rebuild that matches the published attestation hashes:
1. Fork this repository.
2. Add your verification entry to the table above.
3. Sign your Git commit with your GPG/SSH release key.
4. Open a pull request titled `repro: add third-party attestation entry for <commit-sha>`.
