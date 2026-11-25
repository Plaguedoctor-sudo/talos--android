# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Entity Attestation Token (EAT, RFC 9711) Parser and Data Model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class EAToken:
    """Represents a validated RFC 9711 Entity Attestation Token."""
    iss: str
    sub: str
    iat: int
    eat_profile: str
    ueid: str
    hwmodel: str
    swname: str
    dbgstat: str
    boot_count: int
    nonce: str
    measres: Dict[str, str]
    tpm_quote: Dict[str, Any]
    submods: Dict[str, Any] = field(default_factory=dict)
    raw_claims: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "iat": self.iat,
            "eat_profile": self.eat_profile,
            "ueid": self.ueid,
            "hwmodel": self.hwmodel,
            "swname": self.swname,
            "dbgstat": self.dbgstat,
            "boot_count": self.boot_count,
            "nonce": self.nonce,
            "measres": self.measres,
            "tpm_quote": self.tpm_quote,
            "submods": self.submods,
        }


def parse_eat(raw_data: str | bytes | dict[str, Any]) -> EAToken:
    """Parse raw EAT token data (JSON string, bytes, or parsed dict) into EAToken."""
    if isinstance(raw_data, (bytes, bytearray)):
        raw_data = raw_data.decode("utf-8")
    if isinstance(raw_data, str):
        claims = json.loads(raw_data)
    elif isinstance(raw_data, dict):
        claims = raw_data
    else:
        raise TypeError(f"Unsupported EAT input type: {type(raw_data)}")

    required_claims = [
        "iss", "sub", "iat", "eat_profile", "ueid",
        "hwmodel", "swname", "dbgstat", "boot_count",
        "nonce", "measres", "tpm_quote"
    ]
    missing = [c for c in required_claims if c not in claims]
    if missing:
        raise ValueError(f"EAT token missing required RFC 9711 claims: {missing}")

    return EAToken(
        iss=str(claims["iss"]),
        sub=str(claims["sub"]),
        iat=int(claims["iat"]),
        eat_profile=str(claims["eat_profile"]),
        ueid=str(claims["ueid"]),
        hwmodel=str(claims["hwmodel"]),
        swname=str(claims["swname"]),
        dbgstat=str(claims["dbgstat"]),
        boot_count=int(claims["boot_count"]),
        nonce=str(claims["nonce"]),
        measres={str(k): str(v) for k, v in claims["measres"].items()},
        tpm_quote=dict(claims["tpm_quote"]),
        submods=dict(claims.get("submods", {})),
        raw_claims=claims,
    )
