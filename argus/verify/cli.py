from __future__ import annotations
import argparse, json, pathlib, sys, os

# Ensure local dependencies are discoverable
_deps = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.deps"))
if os.path.exists(_deps) and _deps not in sys.path:
    sys.path.insert(0, _deps)
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _root not in sys.path:
    sys.path.insert(0, _root)

from argus.verify import findings as F
from argus.verify.bundle import Bundle, BundleError
from argus.verify.trust import Keyring
from argus.verify import verify as V
from blake3 import blake3

BANNER = {
    "SEALED": "All windows sealed. Absence claims valid.",
    "SEALED+LOCAL_TAGS": "All windows sealed. Absence claims provisional outside single epochs (LOCAL_TAGS).",
    "GAPPED": "Gaps present, all explained. Absence claims valid only inside sealed windows. Check the producer mode line.",
    "GAPPED+LOCAL_TAGS": "Gaps present, all explained. Absence claims provisional outside single epochs (LOCAL_TAGS). Check the producer mode line.",
    "FILTERED": "Case-filtered scope. Absence claims NOT supported.",
    "INDETERMINATE": "Boundary or checkpoint failure. Do not rely on absence.",
}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="argus-verify")
    p.add_argument("bundle", help="Path to .argx bundle directory or tar")
    p.add_argument("--keyring", required=True, help="Path to keyring directory")
    p.add_argument("--strict", action="store_true", help="Fail on any GAP or anomaly")
    p.add_argument("--scope-check", action="store_true", help="Enforce declared scope rules")
    p.add_argument("--format", choices=["human", "jsonl"], default="human")
    p.add_argument("--require-open", action="append", default=[], help="rec:field required open")
    p.add_argument("--min-reveal", type=float, help="Minimum revealed fraction required")
    p.add_argument("--now", help="Freeze wall clock ISO timestamp for determinism")
    p.add_argument("--out", help="Write report to file")
    p.add_argument("--sign-key", help="Private PEM key to sign the report")
    a = p.parse_args(argv)

    try:
        bundle = Bundle.open(pathlib.Path(a.bundle))
    except BundleError as e:
        err_msg = json.dumps({"__fatal__": str(e)})
        if a.format == "jsonl":
            print(err_msg)
        else:
            print(f"FATAL: {e}", file=sys.stderr)
        return 4

    rep = V.run(bundle, Keyring(pathlib.Path(a.keyring)), a.strict,
                a.scope_check, a.require_open, a.min_reveal)

    bundle_id_hex = bundle.manifest.get("bundle_id", b"").hex() if isinstance(bundle.manifest.get("bundle_id"), bytes) else str(bundle.manifest.get("bundle_id", ""))

    if a.format == "jsonl":
        out = []
        for f in rep.ordered():
            out.append(json.dumps({
                "severity": F._SEV_NAME[f.severity], "code": f.code,
                "seg": f.seg_seq, "offset": f.offset, "record": f.record_seq,
                "description": f.description,
            }))
        out.append(json.dumps({"__summary__": {
            "grade": rep.grade, "fatal": rep.count(F.FATAL),
            "defect": rep.count(F.DEFECT), "anomaly": rep.count(F.ANOMALY),
            "notice": rep.count(F.NOTICE),
            "bundle_blake3": bundle.manifest_hash.hex(),
            "revealed_fraction": round(rep.revealed_fraction, 4),
            "exit": rep.exit_code(a.strict),
        }}))
        text = "\n".join(out)
    else:
        lines = ["=" * 60, " ARGUS VERIFY REPORT", "=" * 60,
                 f" bundle_id     {bundle_id_hex}",
                 f" bundle_blake3 {bundle.manifest_hash.hex()}",
                 f" scope         {bundle.manifest.get('scope', 'UNKNOWN')}",
                 f" producer      {rep.producer_mode or 'unknown'}",
                 f" grade         {rep.grade}",
                 f" revealed      {rep.revealed_fraction:.1%}",
                 "-" * 60, " FINDINGS"]
        for f in rep.ordered():
            lines.append(f" {F._SEV_NAME[f.severity].upper():8} {f.code:6} "
                         f"{str(f.seg_seq or '—'):4} {f.description}")
        lines += ["-" * 60,
                  f" COUNTS fatal {rep.count(F.FATAL)} · defect {rep.count(F.DEFECT)} "
                  f"· anomaly {rep.count(F.ANOMALY)} · notice {rep.count(F.NOTICE)}",
                  "-" * 60, " CONCLUSION", " " + BANNER.get(rep.grade, "Unrecognized grade."),
                  "=" * 60]
        text = "\n".join(lines)

    if a.sign_key:
        from cryptography.hazmat.primitives import serialization
        sk = serialization.load_pem_private_key(pathlib.Path(a.sign_key).read_bytes(), None)
        sig = sk.sign(blake3(text.encode()).digest())
        out_base = pathlib.Path(a.out or "report")
        out_base.with_suffix(".sig").write_bytes(sig)

    if a.out:
        pathlib.Path(a.out).write_text(text + "\n")
    else:
        print(text)
    return rep.exit_code(a.strict)


if __name__ == "__main__":
    sys.exit(main())
