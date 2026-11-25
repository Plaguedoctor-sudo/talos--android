# Contributing to TALOS / LibreMobile OS

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

Thank you for your interest in contributing to TALOS / LibreMobile OS, a sovereign commons built to deliver a post-Android mobile computing platform free of corporate surveillance and framework bloat.

---

## 1. Developer Certificate of Origin (DCO)

All contributions to TALOS are accepted under the terms of the **Developer Certificate of Origin (DCO), Version 1.1**. We do not use Contributor License Agreements (CLAs) that transfer copyright away from authors.

To certify compliance with the DCO, sign off on every commit by adding a `Signed-off-by` line:

```
Signed-off-by: Random J. Developer <developer@example.org>
```

You can automatically add this line to git commits using:
```bash
git commit -s -m "feat(subsystem): brief imperative description"
```

---

## 2. Licensing & SPDX Headers

Every contributed source file must include an SPDX license identifier and a copyright notice:

- **C / C++ / Java / Rust:**
  ```c
  // SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
  // SPDX-License-Identifier: GPL-3.0-or-later
  ```
- **Shell / Python / Makefile / TOML / YAML:**
  ```python
  # SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
  # SPDX-License-Identifier: GPL-3.0-or-later
  ```
- **Markdown / HTML / XML:**
  ```markdown
  <!--
  SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
  SPDX-License-Identifier: GPL-3.0-or-later
  -->
  ```

---

## 3. Core Architectural Constraints

Contributions must strictly adhere to the following principles:

1. **Zero-Dependency Philosophy for Native Daemons:**
   - Host mobile daemons (`lrd-*`) must be written in ANSI C (`-O2 -Wall`), strictly avoiding external runtime dependencies (no glib, no dbus daemons in critical sleep paths, no heavy third-party runtimes).
   - Total idle memory footprint for all host daemons combined must stay under 30 MB RSS.
2. **Standard-Library Only for Python Tooling:**
   - Operational security scripts and verification utilities must rely exclusively on the Python 3 standard library unless explicitly approved by the Technical Steering Council.
3. **No Java on the Host OS:**
   - Android Java runtimes (ART, Zygote, SystemServer) remain strictly quarantined inside the isolated Waydroid container.
4. **Hardware-Free Simulation Fallbacks:**
   - Any daemon interacting with physical hardware must provide deterministic simulated fallbacks so tests execute in unprivileged CI/container environments without real hardware.

---

## 4. Review Process & Service Level Agreement (SLA)

- **Initial Review SLA:** Subsystem maintainers commit to providing initial substantive feedback on pull requests within **seventy-two (72) hours** of submission.
- **Lazy Consensus:** If a pull request receives no objections after review by the subsystem maintainer, it may be merged.
- **Pre-Submission Gates:** Pull requests must pass local validation before review:
  ```bash
  make check         # Must pass all 100 tests (mobile + ARGUS trust)
  make reproducible  # Must produce bit-for-bit identical dual-build artifacts
  make reuse-lint    # Must pass SPDX/REUSE license linting
  ```

---

## 5. Submitting Changes

1. Fork the repository and create a feature branch (`feat/telephony-sim-refresh`).
2. Follow conventional commit messages: `feat(telephony): ...`, `fix(wifi): ...`, `docs(governance): ...`.
3. Include test coverage for any new daemon endpoints or CLI commands.
4. Update [`README.md`](file:///home/alpha/android/README.md) and [`AI_CONTEXT.md`](file:///home/alpha/android/AI_CONTEXT.md) for architectural changes.
5. Submit a pull request referencing any relevant issue trackers.
