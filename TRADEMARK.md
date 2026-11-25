# TALOS / LibreMobile OS — Trademark Policy

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

## 1. Purpose & Principles

The marks **"TALOS"**, **"LibreMobile"**, **"LibreDroid"**, and associated graphical logos are protected marks managed by the TALOS Sovereign Commons Foundation.

The primary purpose of this trademark policy is to protect the integrity of the sovereign computing mission. When a user buys a device or flashes a ROM bearing the TALOS or LibreMobile mark, they must have an absolute guarantee that:
1. The system is free of Google Mobile Services and corporate surveillance telemetry;
2. The system complies with the strict 6-aim Foundation Charter;
3. The software matches published bit-for-bit reproducible release attestations.

---

## 2. Permitted Uses (No Prior Approval Required)

You may use the TALOS and LibreMobile marks without written permission for:

1. **Unmodified Redistribution:** Distributing bit-for-bit identical binary releases and system images (`.img`, `.tar.xz`) that match published foundation attestation records and SHA-256 checksums.
2. **Truthful Compatibility Statements:** Describing software or hardware compatibility (e.g., *"Compatible with TALOS OS"*, *"Designed for LibreMobile Treble GSI"*).
3. **Nominative Fair Use & Education:** Educational tutorials, journalistic reporting, academic research papers, and community discussion.
4. **Linking:** Linking to the official project website, documentation, or Git repositories.

---

## 3. Mandatory Fork Naming Rules

Software freedom under the GPL guarantees anyone the right to fork and modify the codebase. However, trademark rights protect users against confusion.

If you produce a modified build, fork, or derivative distribution:

1. **Mandatory Name Change:** You **must remove** the marks "TALOS", "LibreMobile", and "LibreDroid" from the product name, boot animation, launcher branding, and user-facing identity.
2. **Descriptive Attribution Permitted:** You may state in documentation that your project is *"A fork of TALOS OS"* or *"Derived from LibreMobile"*, provided it does not imply endorsement, sponsorship, or official certification by the Foundation.
3. **No False Sovereignty Claims:** Downstream distributions that re-introduce Google Play Services, third-party advertising SDKs, commercial telemetry, or proprietary blobs into the host OS are expressly forbidden from using the TALOS marks or representing themselves as sovereign successors.

---

## 4. Hardware Vendor & Partner Guidelines

Hardware manufacturers wishing to pre-install TALOS on consumer devices and display the "Powered by TALOS" badge must:
1. Join the Foundation as a Hardware Partner Member;
2. Pass 100% of the mobile verification test suite (`make test-mobile`);
3. Provide publicly available, bit-for-bit reproducible build trees verified by Foundation multisig attestations;
4. Maintain unlocked bootloaders and provide un-throttled Fastboot flashing interfaces.

For commercial partnership inquiries:
<!-- TODO(operator): Specify partnership contact email -->
`TODO(operator): Contact partnerships@talos.os for hardware verification agreements.`
