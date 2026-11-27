# Pending Signed Self-Check Ledger Row (Template — Do Not Cite Until Signed)

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

> **Status:** PENDING OFFLINE SIGNATURE — No `.sig` file exists in git yet and **no `SIGNED SELF-CHECK` exists for `62561843aa9e08c14415d0e0f0a963b269ae1a90` until the operator signs offline and commits the detached signature.**

## Row Template for [`repro/THIRD-PARTY-VERIFICATIONS.md`](THIRD-PARTY-VERIFICATIONS.md)

After PR #5 merges, sign [`repro/attestation-62561843aa9e08c14415d0e0f0a963b269ae1a90.json`](attestation-62561843aa9e08c14415d0e0f0a963b269ae1a90.json) offline with the rotated release key, update the timestamp if needed (generated at `2026-11-27T04:28:45Z`), replace `<sig-commit-sha-placeholder>` with the `.sig` commit SHA (or passing [`repro-independent.yml`](https://github.com/Plaguedoctor-sudo/talos--android/actions/workflows/repro-independent.yml) evidence), and append this row to [`repro/THIRD-PARTY-VERIFICATIONS.md`](THIRD-PARTY-VERIFICATIONS.md):

```markdown
| 2026-11-27T04:28:45Z | `62561843aa9e08c14415d0e0f0a963b269ae1a90` | project-signer@offline-workstation | `aa0f4ccac24991c7529c0da6fb6312e5301cfe1ac6c4da38f5c75e86dfe4da58` | SIGNED SELF-CHECK | <sig-commit-sha-placeholder> |
```

## Operator Signing & Verification Commands (Post-Merge)

```bash
cd ~/android
HEAD_SHA=$(git rev-parse HEAD)
python3 store/sign-index.py sign \
  --index  "repro/attestation-${HEAD_SHA}.json" \
  --key    ~/.config/talos/store-signing.sec \
  --output "repro/attestation-${HEAD_SHA}.json.sig"

python3 store/sign-index.py verify \
  --index  "repro/attestation-${HEAD_SHA}.json" \
  --sig    "repro/attestation-${HEAD_SHA}.json.sig" \
  --pubkey store/keys/fdroid-signing.pub

grep -c "SIGNED SELF-CHECK" repro/THIRD-PARTY-VERIFICATIONS.md
```
