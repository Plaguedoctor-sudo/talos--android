# Compromised Signing Key Notice

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

The Ed25519 key with fingerprint d990d9b364f780f4350030968fde559414f0b275e353eb47ebb794fc672ee391 was committed to the repository at commit 82ce129 and MUST be treated as compromised. It must never be pinned by any client. See SECURITY.md for the disclosure process.

### Details
- **Key Algorithm:** Ed25519 (Raw 32-byte seed / detached signature)
- **Compromised Fingerprint:** `d990d9b364f780f4350030968fde559414f0b275e353eb47ebb794fc672ee391`
- **Initial Commit:** `82ce129` (`feat(store): implement antimonopoly F-Droid distribution layer with deterministic privacy scores`)
- **Remediation Status:** Purged from working tree, `.gitignore` guard enacted, `fingerprint.txt` revoked to `UNPINNED`, safe offline provisioning script provided.
