"""argx bundle exporter. FULL scope, sealed by default."""
from __future__ import annotations
import cbor2, fcntl, os, pathlib, shutil, struct, time
from blake3 import blake3
from argus.verify.record import SegHeader, seg_footer, SEGH_LEN, SEGF_LEN
from argus.verify import verify as V
from argus.verify.findings import Report
from .writer import genesis, entry_hash
from .signers import DeviceSigner


class ExportError(RuntimeError):
    pass


class Exporter:
    def __init__(self, ledger_root, out_dir, key_dir, device_key, cp_signer):
        self.root = pathlib.Path(ledger_root)
        self.out = pathlib.Path(out_dir)
        self.keys = pathlib.Path(key_dir)
        self.dev = DeviceSigner(device_key) if device_key else None
        self.cp = cp_signer
        p = self.root / ".ledger_id"
        self.ledger_id = p.read_bytes() if p.exists() else b"\x00" * 32

    def _lock(self):
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                return fd
            except OSError:
                if time.monotonic() > deadline:
                    raise ExportError("ledgerd holds the write lock; stop it first")
                time.sleep(0.1)

    def _assert_checkpoint_key(self):
        from cryptography.hazmat.primitives import serialization as s
        if not (self.keys / "checkpoint.pem").exists():
            return
        if not hasattr(self.cp, "public_key"):
            return
        embedded = s.load_pem_public_key((self.keys / "checkpoint.pem").read_bytes())
        derived = self.cp.public_key()
        a = embedded.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        b = derived.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        if a != b:
            raise ExportError("checkpoint.key does not match keys/checkpoint.pem")

    def _seq_bounds(self, path) -> tuple[int, int]:
        from argus.verify.record import Header, HDR_LEN, SEGF_LEN
        data = path.read_bytes()
        off, end, first, last = SEGH_LEN, len(data) - SEGF_LEN, None, None
        while off + HDR_LEN <= end:
            h = Header.parse(data, off)
            first = h.seq if first is None else first
            last = h.seq
            off += HDR_LEN + h.payload_len
        return (first or 0), (last or 0)

    def _mono_bounds(self, path) -> tuple[int, int]:
        from argus.verify.record import Header, HDR_LEN, SEGF_LEN
        data = path.read_bytes()
        off, end, first, last = SEGH_LEN, len(data) - SEGF_LEN, None, None
        while off + HDR_LEN <= end:
            h = Header.parse(data, off)
            first = h.mono_ns if first is None else first
            last = h.mono_ns
            off += HDR_LEN + h.payload_len
        return (first or 0), (last or 0)

    def _select(self, segs, from_seq, to_seq):
        return [s for s in segs if self._seq_bounds(s)[1] >= from_seq
                and self._seq_bounds(s)[0] <= to_seq]

    def _anchor_beyond(self, last_seq: int) -> int:
        """Ensure a checkpoint exists for a segment after the range."""
        for p in sorted((self.root / "anchors").glob("cp-*.cbor")):
            if int(p.stem[3:]) > last_seq:
                return int(p.stem[3:])
        # append a checkpoint-only segment past the tail
        nxt = last_seq + 1
        segs = sorted(self.root.glob("*.seg"))
        last = segs[-1].read_bytes()
        sh = SegHeader.parse(last)
        prev = self._tail_hash(segs[-1])
        sh2 = SegHeader(ver=1, feed_ver=2, seg_seq=nxt, epoch=sh.epoch,
                        epoch_len=sh.epoch_len, first_seq=0,
                        prev_seg_hash=prev, build_hash=sh.build_hash,
                        boot_id=sh.boot_id, record_count=0)
        (self.root / f"{nxt:06d}.seg").write_bytes(sh2.encode() + seg_footer(prev, 0))
        self.cp(nxt, prev)
        return nxt

    def _tail_hash(self, path) -> bytes:
        from argus.verify.record import Header, HDR_LEN
        data = path.read_bytes()
        sh = SegHeader.parse(data)
        prev, off, end = sh.prev_seg_hash, SEGH_LEN, len(data) - SEGF_LEN
        while off + HDR_LEN <= end:
            h = Header.parse(data, off)
            prev = entry_hash(prev, h)
            off += HDR_LEN + h.payload_len
        return prev

    def run(self, purpose: str, operator: str, scope: str = "FULL",
            seq_range: tuple[int, int] | None = None,
            time_range: tuple[int, int] | None = None) -> pathlib.Path:
        fd = self._lock()
        try:
            return self._run(purpose, operator, scope, seq_range or time_range)
        finally:
            os.close(fd)

    def _run(self, purpose, operator, scope="FULL", seq_range=None):
        self._assert_checkpoint_key()

        p = self.root / ".ledger_id"
        if p.exists():
            self.ledger_id = p.read_bytes()

        if self.out.exists():
            shutil.rmtree(self.out)
        (self.out / "keys").mkdir(parents=True)
        (self.out / "segments").mkdir()
        (self.out / "anchors").mkdir()

        all_segs = sorted(self.root.glob("*.seg"))
        if not all_segs:
            raise ExportError("empty ledger")
        if scope == "RANGE":
            if not seq_range:
                raise ExportError("RANGE scope needs seq_range")
            from_seq, to_seq = seq_range
            segs = self._select(all_segs, from_seq, to_seq)
            if not segs:
                raise ExportError("range selects no segments")
        else:
            segs = all_segs

        last_seq = int(segs[-1].stem)
        beyond = self._anchor_beyond(last_seq)

        all_segs = sorted(self.root.glob("*.seg"))
        if scope == "RANGE":
            from_seq, to_seq = seq_range
            segs = self._select(all_segs, from_seq, to_seq)
            segs = [s for s in segs if int(s.stem) <= last_seq]
        else:
            segs = [s for s in all_segs if int(s.stem) <= last_seq]

        seg_entries, anchor_entries, files = [], [], []
        for s in segs:
            n = int(s.stem)
            if n > last_seq:
                continue
            dest = self.out / "segments" / s.name
            shutil.copyfile(s, dest)
            data = dest.read_bytes()
            sh = SegHeader.parse(data)
            seg_entries.append({"seg_seq": n, "first_seq": sh.first_seq,
                                "last_seq": sh.first_seq + sh.record_count,
                                "expected_record_count": sh.record_count,
                                "file": f"segments/{s.name}",
                                "blake3": blake3(data).digest(), "size": len(data)})
        for p in sorted((self.root / "anchors").glob("cp-*.cbor")):
            n = int(p.stem[3:])
            if n <= beyond:
                dest = self.out / "anchors" / p.name
                shutil.copyfile(p, dest)
                anchor_entries.append({"seg_seq": n, "file": f"anchors/{p.name}"})

        for name in ("root.pem", "device.pem", "device.cert.pem",
                     "checkpoint.pem", "checkpoint.cert.pem"):
            src = self.keys / name
            if src.exists():
                shutil.copyfile(src, self.out / "keys" / name)

        first_data = (self.out / seg_entries[0]["file"]).read_bytes()
        first_sh = SegHeader.parse(first_data)
        b_id_str = first_sh.boot_id.decode("latin1")
        b_hash_hex = first_sh.build_hash.hex()
        device_entry = {"boot_id": b_id_str, "build_hash": b_hash_hex, "model_hash": "talos-phone-01"}

        if scope == "RANGE":
            omitted = []
            first_seq, last_seq = int(segs[0].stem), int(segs[-1].stem)
            before = [s for s in all_segs if int(s.stem) < first_seq]
            after = [s for s in all_segs if int(s.stem) > last_seq]
            if before:
                before_bracket = f"anchors/cp-{first_seq - 1:06d}.cbor" if (self.out / "anchors" / f"cp-{first_seq - 1:06d}.cbor").exists() else None
                omitted.append({"kind": "SEGMENT_RANGE", "from_seg": 0,
                                "to_seg": first_seq - 1, "reason": "before_range",
                                "bracketed_by": before_bracket})
            if after:
                omitted.append({"kind": "SEGMENT_RANGE", "from_seg": last_seq + 1,
                                "to_seg": int(after[-1].stem),
                                "reason": "after_range",
                                "bracketed_by": f"anchors/cp-{beyond:06d}.cbor"})
        else:
            omitted = []

        (self.out / "cover.txt").write_text(
            f"scope {scope}\npurpose {purpose}\noperator {operator}\n"
            f"segments {segs[0].stem}..{segs[-1].stem}\n")
        (self.out / "omissions.cbor").write_bytes(cbor2.dumps(
            {"scope": scope, "omitted": omitted, "chain_gaps_present":
             self._has_gaps(segs)}, canonical=True))
        prod_mode = self._read_producer_mode(segs)
        att = {"conformance": "fixture"}
        if prod_mode is not None:
            att["producer_mode"] = prod_mode
        (self.out / "attestation.cbor").write_bytes(cbor2.dumps(att, canonical=True))
        (self.out / "redactions.cbor").write_bytes(cbor2.dumps({}, canonical=True))

        rep = self._selfverify(seg_entries)
        (self.out / "selfverify.cbor").write_bytes(cbor2.dumps(
            {"defect": rep.count(40), "fatal": rep.count(50)}, canonical=True))

        for p in sorted(self.out.rglob("*")):
            if p.is_file() and p.name != "manifest.cbor":
                files.append({"path": p.relative_to(self.out).as_posix(),
                              "blake3": blake3(p.read_bytes()).digest(),
                              "size": p.stat().st_size})

        man = {"argx_version": 1, "bundle_id": os.urandom(16), "scope": scope,
               "ledger_id": self.ledger_id,
               "device": device_entry,
               "segments": seg_entries, "anchors": anchor_entries,
               "files": files,
               "omissions_digest": blake3((self.out / "omissions.cbor").read_bytes()).digest(),
               "attestation_digest": blake3((self.out / "attestation.cbor").read_bytes()).digest()}
        raw = cbor2.dumps(man, canonical=True)
        (self.out / "manifest.cbor").write_bytes(raw)
        sig = self.dev.sign(blake3(raw).digest())
        (self.out.parent / "bundle.sig").write_bytes(sig)
        (self.out / "bundle.sig").write_bytes(sig)
        (self.out.parent / f"{self.out.name}.sig").write_bytes(sig)
        return self.out

    def _read_producer_mode(self, segs) -> str | None:
        from argus.verify.record import Header, HDR_LEN, SEGF_LEN
        for s in segs:
            data = s.read_bytes()
            off, end = SEGH_LEN, len(data) - SEGF_LEN
            while off + HDR_LEN <= end:
                h = Header.parse(data, off)
                if h.type == 0x0F08:
                    try:
                        p_data = data[off + HDR_LEN : off + HDR_LEN + h.payload_len]
                        fields = cbor2.loads(p_data)
                        for f in fields:
                            if isinstance(f, dict) and f.get("name") == "mode":
                                val = f.get("v")
                                return val.decode() if isinstance(val, (bytes, bytearray)) else str(val)
                    except Exception:
                        pass
                off += HDR_LEN + h.payload_len
        return None

    def _has_gaps(self, segs) -> bool:
        from argus.verify.record import Header, HDR_LEN, SEGF_LEN
        for s in segs:
            data = s.read_bytes()
            off, end = SEGH_LEN, len(data) - SEGF_LEN
            while off + HDR_LEN <= end:
                h = Header.parse(data, off)
                if h.type == 0x0F01:
                    return True
                off += HDR_LEN + h.payload_len
        return False

    def _selfverify(self, seg_entries):
        rep = Report()
        from argus.verify.bundle import Bundle
        from argus.verify.trust import Keyring
        try:
            b = Bundle(self.out)
        except Exception as e:
            rep.add(50, "V-602", str(e))
            return rep
        return V.run(b, Keyring(self.out / "keys"), False, True, [], None)
