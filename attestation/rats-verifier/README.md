<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-4.0
-->

# RATS Verifier (RFC 9334 & RFC 9711)

A zero-dependency, pure Python 3 stdlib reference verifier for sovereign remote attestation on TALOS / LibreMobile OS.

## Overview
This subsystem implements the Verifier role in the **Remote ATtestation ProcedureS (RATS)** architecture (IETF RFC 9334). It parses **Entity Attestation Tokens (EAT)** (IETF RFC 9711), validates hardware TPM 2.0 quotes against pinned Attestation Keys (AKs), checks PCR measurements against Reference Integrity Measurements (RIM), and emits formal Trustworthiness Vectors.

## Features
- **Zero Runtime Dependencies:** Built strictly using Python 3 stdlib (`hashlib`, `hmac`, `json`, `struct`, `base64`).
- **Cryptographic Quote Verification:** Verifies `TPMS_ATTEST` integrity quotes using pinned AKs (supporting RSA-SHA256 and HMAC-SHA256).
- **PCR Digest Verification:** Validates that `pcrDigest` in the TPM quote corresponds to the cryptographic hash of measured PCR registers.
- **RFC 9334 Attestation Results:** Outputs standardized verdicts (`AFFIRMED`, `CONTRAINDICATED`, `UNDETERMINED`) alongside structured trustworthiness evaluations.

## Usage
```bash
# Verify an EAT token against pinned AK and RIM
python3 -m attestation.rats_verifier.cli verify \
    --token attestation/rats-verifier/vectors/valid_eat_token.json \
    --ak-name "talos-ref-ak-01" \
    --nonce "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

## Operator Guidance
`TODO(operator): Provision hardware-backed Endorsement Key (EK) certificates and deploy production TPM 2.0 Attestation Keys (AK) signed by OEM/foundation CAs.`
