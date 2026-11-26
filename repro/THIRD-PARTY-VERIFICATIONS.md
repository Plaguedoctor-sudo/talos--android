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
| 2026-11-25 09:45:00 UTC | `cce901dfa964d9ffe3f1d85186c7cb4173c61570` | self (github-actions@ubuntu-24.04) | `dd00921a1ee2c3acaa1379e31acc15ba3a1dab97c2eb1316c6e22a2a3f2fe8db` | UNSIGNED SELF-CHECK | [repro-independent.yml](https://github.com/Plaguedoctor-sudo/talos--android/actions/workflows/repro-independent.yml) |
| 2026-11-26T10:01:20Z | `cce901dfa964d9ffe3f1d85186c7cb4173c61570` | project-signer@offline-workstation | `f28831a6e60e3bcf070138a74a754596d80df1b5355eecc03d3731181047e4cf` | SIGNED SELF-CHECK | cce901dfa964d9ffe3f1d85186c7cb4173c61570 |

> **Status legend**
>
> - **UNSIGNED SELF-CHECK** — The project's own CI built the commit and verified the result against itself. This is a *consistency* check, not a trust signal. It proves the build is deterministic on that runner, nothing more. It does not prove that the published binaries match the source, because no signing key has yet attested to either.
> - **SIGNED SELF-CHECK** — The project's CI verified a build against an attestation that was signed by the TALOS offline release root key. This is a meaningful signal that the running binaries match the source, but only if the signer is trusted.
> - **INDEPENDENT VERIFICATION** — A party other than the project (different legal entity, different hardware, different operator) rebuilt from source and matched the signed attestation. This is the strongest signal and the only one that survives the question "what if the maintainers themselves are compromised?"
>
> As of the current commit, **there are zero SIGNED SELF-CHECKS and zero INDEPENDENT VERIFICATIONS**. The store signing key is UNPINNED (see `store/keys/fingerprint.txt`) and no release root key has been provisioned. No trust signal has yet been produced by this ledger.

### Automated Ledger Update Mechanism
When `repro-independent.yml` verifies a rebuild in CI against a published attestation record:
1. The workflow generates a verifiable proof entry formatted as:
   `| <UTC> | <release-sha> | self (github-actions@<runner-id>) | <attestation-hash> | UNSIGNED SELF-CHECK | <run-url> |`
   (Emits `SIGNED SELF-CHECK` only when `store/keys/fingerprint.txt` is not `UNPINNED` and the attestation carries a valid detached signature from that pinned key.)
2. Build output hashes are stored and uploaded as a immutable workflow artifact (`repro-hashes-<sha>`).
3. External verifiers or bot automations submit signed ledger PRs referencing the GitHub Actions run URL. Never silently rewrite `main` from CI without peer review.

---

## How to Submit an Independent Attestation
If you have performed an independent rebuild that matches the published attestation hashes:
1. Fork this repository.
2. Add your verification entry to the table above.
3. Sign your Git commit with your GPG/SSH release key.
4. Open a pull request titled `repro: add third-party attestation entry for <commit-sha>`.
