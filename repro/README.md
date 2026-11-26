# TALOS / LibreMobile OS — Reproducible Builds & Attestation

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Objective:** Guarantee that any independent third party can compile TALOS / LibreMobile OS from source and arrive at the exact same bit-for-bit binary artifacts (`.img`, `.tar.xz`, and native C daemons), with cryptographic proof via machine-verifiable attestation JSON records.

---

## 1. Third-Party Rebuild in One Command

An auditor or downstream user can independently verify and reproduce the entire operating system image in a single command using any of the following three workflows:

### Method A: Hermetic Nix Environment (Primary & Recommended)

Using the pinned Nix flake (`nixpkgs` release `nixos-23.11` via `flake.lock`):

```bash
# Clone the repository
git clone https://github.com/talos-os/android.git && cd android

# Execute dual-build reproducibility verification inside hermetic nix shell
nix develop --command make reproducible
```

Or build the target directly with pure Nix:
```bash
nix build
```

---

### Method B: Pinned Container Environment (Fallback)

Using the digest-pinned `debian:bookworm-slim` image:

```bash
# Run one-command reproducible build and attestation verification
make reproducible-docker
```

Or directly via Docker/Podman:
```bash
docker build -t talos-repro -f repro/Dockerfile .
docker run --rm talos-repro
```

---

### Method C: Native Linux Workstation

On any Linux machine with standard build tools (`gcc`, `make`, `python3`, `nodejs`, `e2fsprogs`):

```bash
# 1. Run dual build (Path A vs Path B) and generate attestation
make reproducible

# 2. Verify all artifacts against the generated attestation
python3 repro/verify-attestation.py repro/attestation-$(git rev-parse HEAD).json out/a
```

---

## 2. Deterministic Build Pillars

TALOS achieves bit-for-bit reproducibility through three strict technical guardrails implemented in [scripts/repro-build.sh](file:///home/alpha/android/scripts/repro-build.sh):

1. **Epoch & Locale Pinning**:
   - `SOURCE_DATE_EPOCH` is derived from the latest git commit timestamp (`git log -1 --format=%ct`).
   - `TZ=UTC` and `LC_ALL=C` are forced globally across all sub-processes.
   - `E2FSPROGS_FAKE_TIME` binds ext4 metadata creation timestamps.

2. **C Toolchain Determinism**:
   - `-ffile-prefix-map=$PWD=.` and `-fdebug-prefix-map=$PWD=.` strip host working directory paths from ELF debug tables and symbol strings.
   - `-Wl,--build-id=sha1` ensures deterministic cryptographic linker build IDs.

3. **Archive & Filesystem Normalization**:
   - `tar`: Packaged with `--sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner` to normalize directory ordering, UIDs, and timestamps.
   - `ext4`: Formatted with `-E hash_seed=$SEED,root_owner=0:0,lazy_itable_init=0` and `-U $UUID` derived deterministically from `SOURCE_DATE_EPOCH`.
   - Inode metadata (`ctime` and sub-second extra fields) are normalized post-creation to ensure path and host invariant hashes.

---

## 3. Verifying an Attestation Record

Every execution of `make reproducible` outputs an attestation JSON in [repro/](file:///home/alpha/android/repro) named `attestation-<git-sha>.json`.

To audit a local build directory (e.g. `out/a`) against an attestation record:

```bash
python3 repro/verify-attestation.py repro/attestation-<git-sha>.json out/a
```

### Attestation Schema
The attestation JSON follows this schema:
```json
{
  "$schema": "https://talos.os/schemas/repro-attestation-v1.json",
  "git_sha": "36901f9ccb24e6c10d29abeda70b780ea9cef782",
  "source_date_epoch": 1795613038,
  "build_env_hash": "2f6c8d7e0031ab9...",
  "build_environment": {
    "gcc": "gcc (Debian 12.2.0-14) 12.2.0",
    "make": "GNU Make 4.3",
    "mke2fs": "mke2fs 1.47.0 (5-Feb-2023)",
    "node": "v20.18.0",
    "python3": "Python 3.12.3"
  },
  "diff_result": "IDENTICAL",
  "artifacts_verified_count": 20,
  "per_artifact_sha256": {
    "images/libredroid-mobile-arm64-treble.img": "4be9363e8a7fd056...",
    "daemons/lrd-telephonyd": "8e082f674c3e2532...",
    ...
  }
}
```

---

## 4. Published Artifact Verification Table

Artifacts audited and matched bit-for-bit:

| Category | Artifact Path | Description |
| :--- | :--- | :--- |
| **System Image** | `images/libredroid-mobile-arm64-treble.img` | Generic System Image (GSI ext4) for ARM64 Treble devices |
| **Release Rootfs** | `release/libremobile-arm64-generic.img` | Bit-for-bit copy staged for bare-metal flashers |
| **Device Packages** | `release/libremobile-1.0-rc-vidofnir.tar.xz` | Halium/GKI release tarball for OnePlus / Dimensity |
| **Device Packages** | `release/libremobile-1.0-rc-OP5DA6L1.tar.xz` | Halium/GKI release tarball for Snapdragon 8 Gen devices |
| **Telephony** | `daemons/lrd-telephonyd` & `lrd-telephony` | Native VoLTE/VoNR, SIM PIN, SMS cellular daemons |
| **Bluetooth** | `daemons/lrd-bluetoothd` & `lrd-bluetooth` | BlueZ D-Bus, A2DP, and BLE anti-tracking MAC rotator |
| **Wi-Fi** | `daemons/lrd-wifid` & `lrd-wifi` | WPA3 station & mobile hotspot AP tethering daemons |
| **Firewall** | `daemons/lrd-firewalld` & `lrd-firewall` | Defense-grade egress firewall & panic cutoff |
| **Sensors** | `daemons/lrd-sensord` | Linux IIO motion & orientation matrix controller |
| **Power** | `daemons/lrd-wakelockd` | Pouch-cell wakelock & S2Idle sleep governor |
| **Metadata** | `release/verity-table.json` | dm-verity cryptographic verification parameters |
| **Manifest** | `SHA256SUMS.txt` | Complete cryptographic hash digest index |

> **TODO(operator):** Sign release attestations with the official TALOS Ed25519 offline root key using `signify` or `gpg --detach-sign`.

---

## 5. Third-Party Independent Verification

An attestation is only meaningful when verified by a machine that is not the one that produced it. The GitHub Actions job `repro-independent` runs this verification on every push.

### Exact Instructions for External Verifiers
If you are an external auditor, downstream packager, or community verifier auditing on a clean, independent machine:

```bash
# 1. Fresh clone on clean hardware
git clone https://github.com/Plaguedoctor-sudo/talos--android.git
cd talos--android

# 2. Execute bit-for-bit build in pinned container
make reproducible-docker

# 3. Verify resulting artifacts against committed attestation
python3 repro/verify-attestation.py repro/attestation-$(git rev-parse HEAD).json out/a
```

### Public Verification Ledger
Independent verifiers who successfully reproduce the binary artifacts are encouraged to log their results in the public ledger:
- **[repro/THIRD-PARTY-VERIFICATIONS.md](file:///home/alpha/android/repro/THIRD-PARTY-VERIFICATIONS.md)**

A ledger entry labeled UNSIGNED SELF-CHECK is not a trust signal. It is a record that the project's own CI ran a consistency check. Do not cite this ledger as evidence of trustworthiness until at least one SIGNED SELF-CHECK and one INDEPENDENT VERIFICATION entry exist.

### Reporting Hash Discrepancies
If your build produces non-identical artifact digests, do not ignore the deviation. Submit a detailed discrepancy report using the structured issue template:
- **[.github/ISSUE_TEMPLATE/repro-mismatch.yml](file:///home/alpha/android/.github/ISSUE_TEMPLATE/repro-mismatch.yml)**
