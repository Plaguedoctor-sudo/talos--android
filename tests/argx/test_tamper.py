import pathlib, shutil, subprocess, sys
import cbor2

HERE = pathlib.Path(__file__).parent
FIX = HERE / "fixtures" / "basic.argx"


from collections import namedtuple
CliResult = namedtuple("CliResult", ["returncode", "stdout", "stderr"])


def run(bundle: pathlib.Path, *extra):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    from argus.verify import cli
    cmd_args = [str(bundle), "--keyring", str(HERE / "fixtures" / "keyring")] + list(extra)
    f_out, f_err = io.StringIO(), io.StringIO()
    with redirect_stdout(f_out), redirect_stderr(f_err):
        code = cli.main(cmd_args)
    return CliResult(code, f_out.getvalue(), f_err.getvalue())


def _copy(tmp_path):
    d = tmp_path / "b.argx"
    shutil.copytree(FIX, d)
    # Also replicate signatures so detached verification finds them
    sig_candidates = [
        FIX.parent / f"{FIX.name}.sig",
        FIX.parent / "bundle.sig",
        FIX / "bundle.sig",
    ]
    for s in sig_candidates:
        if s.exists():
            shutil.copyfile(s, tmp_path / "b.argx.sig")
            shutil.copyfile(s, tmp_path / "bundle.sig")
            shutil.copyfile(s, d / "bundle.sig")
            break
    return d


def test_clean():
    code, out, _ = run(FIX, "--scope-check")
    # Clean run with GAP is grade GAPPED; exit code is 1 (explained gaps) or 0 (sealed)
    assert code in (0, 1), out
    assert "SEALED" in out or "GAPPED" in out


def test_truncate_tail(tmp_path):
    d = _copy(tmp_path)
    segs = sorted((d / "segments").glob("*.seg"))
    segs[-1].unlink()
    m = cbor2.loads((d / "manifest.cbor").read_bytes())
    m["segments"] = [s for s in m["segments"] if s["seg_seq"] != int(segs[-1].stem)]
    (d / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))
    code, out, _ = run(d)
    assert code == 2, out
    assert "V-503" in out or "V-203" in out


def test_flip_payload_byte(tmp_path):
    d = _copy(tmp_path)
    seg = sorted((d / "segments").glob("*.seg"))[0]
    data = bytearray(seg.read_bytes())
    data[200] ^= 0xFF
    seg.write_bytes(bytes(data))
    code, out, _ = run(d)
    assert code == 2, out
    assert "V-101" in out


def test_full_scope_with_omission(tmp_path):
    d = _copy(tmp_path)
    (d / "omissions.cbor").write_bytes(cbor2.dumps(
        {"scope": "FULL", "omitted": [{"kind": "SEGMENT_RANGE",
                                       "from_seg": 0, "to_seg": 9,
                                       "reason": "x"}],
         "chain_gaps_present": False}, canonical=True))
    code, out, _ = run(d, "--scope-check")
    assert "V-701" in out


def test_determinism(tmp_path):
    a = run(FIX, "--now", "2026-11-23T00:00:00Z", "--format", "jsonl")
    b = run(FIX, "--now", "2026-11-23T00:00:00Z", "--format", "jsonl")
    assert a[1] == b[1]
