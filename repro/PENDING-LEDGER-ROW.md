# Pending Signed Self-Check Ledger Row (Template — Do Not Cite Until Signed)

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

> **Status:** PENDING OFFLINE SIGNATURE — No `.sig` file exists in git yet and **no `SIGNED SELF-CHECK` exists for `f88f82e423237eb2aae8c5e3213c38cb1ff163a9` until the operator signs offline and commits the detached signature.**

## Row Template for [`repro/THIRD-PARTY-VERIFICATIONS.md`](THIRD-PARTY-VERIFICATIONS.md)

After PR merge, sign [`repro/attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json`](attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json) offline with the rotated release key, replace `<SIGNING_UTC>` with the UTC signing timestamp (`date -u +"%Y-%m-%dT%H:%M:%SZ"`), and append this row to [`repro/THIRD-PARTY-VERIFICATIONS.md`](THIRD-PARTY-VERIFICATIONS.md):

```markdown
| <SIGNING_UTC> | `f88f82e423237eb2aae8c5e3213c38cb1ff163a9` | project-signer@offline-workstation | `279cbfb8e911033b3af9d7b405433ddfa1421436ad01306341051755853ef2e4` | SIGNED SELF-CHECK | f88f82e423237eb2aae8c5e3213c38cb1ff163a9 |
```

*(Note: Once verified in CI after `.sig` lands, the `Run URL / Evidence` column may also reference the passing [`repro-independent.yml`](https://github.com/Plaguedoctor-sudo/talos--android/actions/workflows/repro-independent.yml) run URL.)*

## Operator Signing & Verification Commands (Post-Merge)

```bash
python3 store/sign-index.py sign \
  --index repro/attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json \
  --key ~/.config/talos/store-signing.sec \
  --output repro/attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json.sig

python3 store/sign-index.py verify \
  --index repro/attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json \
  --sig repro/attestation-f88f82e423237eb2aae8c5e3213c38cb1ff163a9.json.sig \
  --pubkey store/keys/fdroid-signing.pub

grep -c "SIGNED SELF-CHECK" repro/THIRD-PARTY-VERIFICATIONS.md
```
