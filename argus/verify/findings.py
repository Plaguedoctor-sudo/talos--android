from __future__ import annotations
from dataclasses import dataclass, field

INFO, NOTICE, ANOMALY, DEFECT, FATAL = 10, 20, 30, 40, 50
SEV = {INFO: "info", NOTICE: "notice", ANOMALY: "anomaly",
       DEFECT: "defect", FATAL: "fatal"}
_SEV_NAME = SEV


@dataclass(frozen=True)
class Finding:
    severity: int
    code: str
    description: str
    seg_seq: int | None = None
    offset: int | None = None
    record_seq: int | None = None

    def sort_key(self):
        return (self.seg_seq if self.seg_seq is not None else -1,
                self.offset if self.offset is not None else -1, self.code)


@dataclass
class Report:
    findings: list = field(default_factory=list)
    grade: str = "INDETERMINATE"
    local_tags: bool = False
    revealed_fraction: float = 0.0
    producer_mode: str | None = None

    def add(self, sev, code, desc, seg_seq=None, offset=None, record_seq=None):
        self.findings.append(Finding(sev, code, desc, seg_seq, offset, record_seq))

    def count(self, sev):
        return sum(1 for f in self.findings if f.severity == sev)

    def ordered(self):
        return sorted(self.findings, key=Finding.sort_key)

    def exit_code(self, strict):
        if self.count(FATAL):
            return 3 if any(f.code.startswith("V-5") for f in self.findings) else 2
        if self.count(DEFECT):
            return 2
        if self.count(ANOMALY):
            return 2 if strict else 1
        if self.grade.startswith("GAPPED"):
            return 2 if strict else 1
        if self.count(NOTICE) and strict:
            return 2
        return 0
