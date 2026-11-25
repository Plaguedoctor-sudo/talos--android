# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Sovereign RATS Verifier (RFC 9334 & RFC 9711)."""

from .eat import EAToken, parse_eat
from .tpm import TPMQuote, verify_quote_signature, compute_pcr_digest
from .verifier import RATSVerifier, AttestationResult, TrustworthinessVector

__all__ = [
    "EAToken",
    "parse_eat",
    "TPMQuote",
    "verify_quote_signature",
    "compute_pcr_digest",
    "RATSVerifier",
    "AttestationResult",
    "TrustworthinessVector",
]
