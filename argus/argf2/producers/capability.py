"""Kernel feature probe. Refuses to start rather than run blind."""
from __future__ import annotations
import os, pathlib, subprocess

CAP_AUDIT_READ = 37

DEGRADED, BPF, AUDIT = "degraded", "bpf", "audit"


def _has_cap(bit: int) -> bool:
    try:
        for line in pathlib.Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) >> bit & 1)
    except Exception:
        return False
    return False


def _audit_available() -> bool:
    return pathlib.Path("/proc/self/net/netlink").exists() and _has_cap(CAP_AUDIT_READ)


def _bpf_available() -> bool:
    return (pathlib.Path("/sys/fs/bpf").exists()
            and pathlib.Path("/sys/kernel/btf/vmlinux").exists())


def _audit_rules_loaded() -> bool:
    try:
        out = subprocess.run(["auditctl", "-l"], capture_output=True, text=True,
                             timeout=3).stdout
        return "argf_exec" in out and "argf_flow" in out
    except Exception:
        return False


class Capabilities:
    def __init__(self):
        self.audit = _audit_available()
        self.audit_rules = _audit_rules_loaded() if self.audit else False
        self.bpf = _bpf_available()

    def resolve(self) -> tuple[str, str]:
        """Return (mode, reason). Never raises."""
        if self.audit and self.audit_rules:
            return AUDIT, "audit rules loaded"
        if self.audit:
            return AUDIT, "audit socket up, argf rules missing (partial)"
        if self.bpf:
            return BPF, "bpf/btf present, audit unavailable"
        return DEGRADED, "no audit socket and no bpf; class K unavailable"

    def require_audit(self) -> None:
        if not self.audit:
            raise RuntimeError(
                "class K producers unavailable: needs CAP_AUDIT_READ and a "
                "NETLINK_AUDIT socket. Ledger degrades to class S/A only.")
        if not self.audit_rules:
            raise RuntimeError(
                "argf_exec/argf_flow audit rules not loaded; install "
                "producers/argf.rules before starting.")

    def mode(self) -> str:
        return self.resolve()[0]
