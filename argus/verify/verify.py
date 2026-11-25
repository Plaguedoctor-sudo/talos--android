"""The nine phases of verification with ARGF/2 and tag_commit validation."""
from __future__ import annotations
import pathlib, struct
import cbor2
from . import findings as F
from .bundle import Bundle
from .record import (
    Header, HDR_LEN, SegHeader, SegFooter, leaf, walk, MAX_FIELDS,
    tag_value, tag_leaf, tag_digest, SCOPE_LOCAL, SCOPE_GLOBAL,
    SEG_MAGIC, SEGF_MAGIC, SEGH_LEN, SEGF_LEN, ledger_root
)
from .trust import Keyring, load_pubkey, load_cert, cert_signed_by, verify_detached, fingerprint
from blake3 import blake3

NORM_REGISTRY_VER = 1


def _entry_hash(prev: bytes, hdr: Header) -> bytes:
    return blake3(prev + hdr.head112()).digest()


def _parse_segment(path: pathlib.Path, report: F.Report, expected_seq: int) -> tuple[SegHeader | None, bytes, bytes | None]:
    raw = path.read_bytes()
    if raw[:4] == SEG_MAGIC:
        try:
            sh = SegHeader.parse(raw)
        except ValueError as e:
            report.add(F.FATAL, "V-104", f"bad segment header: {e}", seg_seq=expected_seq)
            return None, b"", None
        if sh.seg_seq != expected_seq:
            report.add(F.DEFECT, "V-606", f"segment header seq {sh.seg_seq} != filename {expected_seq}",
                       seg_seq=expected_seq)
        if len(raw) < SEGH_LEN + SEGF_LEN:
            report.add(F.DEFECT, "V-104", "segment file shorter than header + footer",
                       seg_seq=expected_seq)
            return sh, b"", None
        body = raw[SEGH_LEN: len(raw) - SEGF_LEN]
        footer_raw = raw[len(raw) - SEGF_LEN:]
        sf = None
        try:
            sf = SegFooter.parse(footer_raw)
            return sh, body, sf.closing_hash
        except Exception:
            return sh, body, None
    elif len(raw) >= 72 and raw[-72:-68] == b"AFTR":
        sh = SegHeader(seg_seq=expected_seq, epoch=0, epoch_len=7)
        body = raw[:-72]
        closing_hash = raw[-68:-36]
        return sh, body, closing_hash
    else:
        sh = SegHeader(seg_seq=expected_seq, epoch=0, epoch_len=7)
        return sh, raw, None


def _walk_records(data: bytes, report: F.Report, seg_seq: int) -> list[Header]:
    headers, off = [], 0
    while off < len(data):
        if off + HDR_LEN > len(data):
            report.add(F.DEFECT, "V-104", f"truncated record header at {off:#x}",
                       seg_seq=seg_seq, offset=off)
            break
        try:
            h = Header.parse(data, off)
        except ValueError as e:
            report.add(F.DEFECT, "V-104", f"bad header at {off:#x}: {e}",
                       seg_seq=seg_seq, offset=off)
            break
        if h.ver != 2:
            report.add(F.DEFECT, "V-104", f"unsupported feed_ver {h.ver}",
                       seg_seq=seg_seq, offset=off)
        body = data[off + HDR_LEN: off + HDR_LEN + h.payload_len]
        if len(body) != h.payload_len:
            report.add(F.DEFECT, "V-101", "truncated payload",
                       seg_seq=seg_seq, offset=off)
            break
        try:
            body_items = cbor2.loads(body)
            if isinstance(body_items, list):
                for item in body_items:
                    if isinstance(item, dict) and item.get("cls") == "open":
                        if "v" in item and "s" in item and "path" in item and "path_dirs" in item:
                            start_leaf = leaf(h.nonce, item["i"], item.get("name", ""), item["v"], item["s"])
                            if walk(item["path"], item["path_dirs"], start_leaf) != h.payload_root:
                                report.add(F.DEFECT, "V-101", f"payload leaf mismatch at {off + HDR_LEN:#x}",
                                           seg_seq=seg_seq, offset=off)
        except Exception as e:
            report.add(F.DEFECT, "V-101", f"corrupt payload at {off:#x}: {e}",
                       seg_seq=seg_seq, offset=off)
        headers.append(h)
        off += HDR_LEN + h.payload_len
    return headers


def _phase_7c(data: bytes, headers: list[Header], sh: SegHeader, report: F.Report, seg_seq: int):
    """Tag structure validation, epoch agreement, and tag_digest binding."""
    tleaves = []
    seen_of = {}

    for h in headers:
        off = data.find(h.encode())
        if off == -1:
            continue
        try:
            payload = cbor2.loads(data[off + HDR_LEN: off + HDR_LEN + h.payload_len])
        except Exception:
            continue
        rec_tleaves = []
        for entry in payload:
            if not isinstance(entry, dict) or entry.get("cls") != "tag":
                continue
            try:
                if entry.get("scope") not in (SCOPE_LOCAL, SCOPE_GLOBAL):
                    raise ValueError(f"invalid tag scope {entry.get('scope')}")
                if len(entry.get("v", b"")) != 16:
                    raise ValueError("tag length must be 16 bytes")
                if entry.get("epoch") != sh.epoch:
                    report.add(F.DEFECT, "V-919",
                               f"tag epoch {entry.get('epoch')} != segment {sh.epoch}",
                               seg_seq=seg_seq, record_seq=h.seq)
                if entry.get("norm_ver", 0) < NORM_REGISTRY_VER:
                    report.add(F.NOTICE, "V-911",
                               f"norm_ver {entry.get('norm_ver')} older than registry {NORM_REGISTRY_VER}",
                               seg_seq=seg_seq, record_seq=h.seq)
                tl = tag_leaf(h.nonce, entry["i"], entry.get("name", "tag"), entry["scope"],
                              entry["norm_ver"], entry["epoch"], entry["v"])
                rec_tleaves.append(tl)
                tleaves.append((h.seq, tl, entry))
                if entry.get("of") is not None:
                    seen_of.setdefault(h.seq, []).append(entry)
            except Exception as e:
                report.add(F.DEFECT, "V-910", f"tag malformed: {e}",
                           seg_seq=seg_seq, record_seq=h.seq)

        if rec_tleaves:
            expected_digest = tag_digest(rec_tleaves)
            if h.reserved != expected_digest:
                report.add(F.DEFECT, "V-910",
                           f"tag_digest mismatch in record {h.seq}",
                           seg_seq=seg_seq, record_seq=h.seq)

    return tleaves, seen_of


def _phase_7d(proof_dir: pathlib.Path, seg_index: dict, report: F.Report) -> set[tuple[int, int]]:
    """Bridge verification."""
    bridged_records = set()
    if not proof_dir.exists():
        return bridged_records

    for pf in sorted(proof_dir.glob("bridge-*.cbor")):
        try:
            b = cbor2.loads(pf.read_bytes())
        except Exception as e:
            report.add(F.DEFECT, "V-912", f"bridge unparseable {pf.name}: {e}")
            continue

        keys = {int(k): v for k, v in b.get("epoch_keys", {}).items()}
        for k in sorted(keys):
            report.add(F.NOTICE, "V-914", f"bridge {pf.name} reveals epoch {k}")

        rec_a, fld_a = b.get("record_seq_a"), b.get("field_a")
        rec_b, fld_b = b.get("record_seq_b"), b.get("field_b")
        bridged_records.add((rec_a, rec_b))

        for side, rec, fld in (("a", rec_a, fld_a), ("b", rec_b, fld_b)):
            loc = seg_index.get(rec)
            if loc is None:
                report.add(F.DEFECT, "V-912",
                           f"bridge {pf.name} references missing record {rec}")
                continue
            seg_seq, payload, h = loc
            entry = next((e for e in payload if isinstance(e, dict) and e.get("i") == fld), None)
            if entry is None or entry.get("cls") != "tag":
                report.add(F.DEFECT, "V-913",
                           f"bridge {pf.name} side {side} field is not a tag")
                continue
            ek = keys.get(entry.get("epoch"))
            if ek is None:
                report.add(F.DEFECT, "V-912",
                           f"bridge {pf.name} missing epoch key {entry.get('epoch')}")
                continue
            if tag_value(ek, b["value"]) != entry.get("v"):
                report.add(F.DEFECT, "V-912",
                           f"bridge {pf.name} side {side} mismatch",
                           seg_seq=seg_seq, record_seq=rec)

    return bridged_records


def run(bundle: Bundle, keyring: Keyring, strict: bool, scope_check: bool,
        require_open: list[str], min_reveal: float | None) -> F.Report:
    rep = F.Report()
    man = bundle.manifest

    # Phase 2 — Trust
    try:
        root_pub = load_pubkey((bundle.root / "keys/root.pem").read_bytes())
        root_fp = fingerprint(root_pub)
        dev_cert = load_cert((bundle.root / "keys/device.cert.pem").read_bytes())
        cp_cert = load_cert((bundle.root / "keys/checkpoint.cert.pem").read_bytes())
        dev_pub = load_pubkey((bundle.root / "keys/device.pem").read_bytes())
        cp_pub = load_pubkey((bundle.root / "keys/checkpoint.pem").read_bytes())
        for cert, pub, label in ((dev_cert, dev_pub, "device"), (cp_cert, cp_pub, "checkpoint")):
            if not cert_signed_by(cert, root_pub):
                rep.add(F.FATAL, "V-502", f"{label} cert not signed by bundle root")
            if fingerprint(pub) not in keyring.keys and strict:
                rep.add(F.FATAL, "V-502", f"{label} key not pinned in keyring")
        if keyring.roots and root_fp not in keyring.roots:
            rep.add(F.FATAL, "V-502", f"root {root_fp} not in allowed_roots")
    except Exception as e:
        rep.add(F.FATAL, "V-502", f"trust chain unusable: {e}")
        return rep

    # Phase 3 — Anchor coverage
    anchors = sorted(man.get("anchors", []), key=lambda a: a["seg_seq"])
    segs = sorted(man.get("segments", []), key=lambda s: s["seg_seq"])
    if not segs:
        rep.add(F.DEFECT, "V-606", "no segments declared in manifest")
        return rep
    if not any(a["seg_seq"] > segs[-1]["seg_seq"] for a in anchors):
        rep.add(F.DEFECT, "V-503", "no checkpoint beyond last exported segment")

    for a in anchors:
        cp_path = bundle.root / a.get("file", f"anchors/cp-{a['seg_seq']:06d}.cbor")
        if not cp_path.exists():
            rep.add(F.DEFECT, "V-501", f"checkpoint missing: {a.get('file', cp_path.name)}")
            continue
        try:
            cp = cbor2.loads(cp_path.read_bytes())
            if cp.get("seg_seq") != a["seg_seq"]:
                raise ValueError("seg_seq mismatch")
            signed_data = blake3(struct.pack("<I", cp["seg_seq"]) + cp["closing_hash"]).digest()
            if not (verify_detached(cp_pub, cp["sig"], cp["closing_hash"]) or
                    verify_detached(cp_pub, cp["sig"], signed_data)):
                rep.add(F.FATAL, "V-501", f"checkpoint signature invalid in {cp_path.name}")
        except Exception as e:
            rep.add(F.DEFECT, "V-501", f"checkpoint malformed {cp_path.name}: {e}")

    # Phase 4 — Integrity & Bundle Signature
    bundle.check_integrity(rep)
    orig = getattr(bundle, "orig_path", bundle.root)
    sig_candidates = [
        bundle.root.parent / f"{bundle.root.name}.sig",
        bundle.root.parent / "bundle.sig",
        bundle.root / "bundle.sig",
        orig.parent / f"{orig.name}.sig",
        orig.parent / "bundle.sig",
        orig / "bundle.sig",
    ]
    sig_path = next((p for p in sig_candidates if p.is_file()), None)
    if not sig_path:
        rep.add(F.FATAL, "V-604", "bundle.sig missing")
    elif not verify_detached(dev_pub, sig_path.read_bytes(), bundle.manifest_hash):
        rep.add(F.FATAL, "V-604", "bundle.sig invalid")

    producer_mode = None
    try:
        att = cbor2.loads((bundle.root / "attestation.cbor").read_bytes())
        producer_mode = att.get("producer_mode")
    except Exception:
        rep.add(F.NOTICE, "V-903", "attestation unreadable")
    rep.producer_mode = producer_mode

    # Phase 5 — Scope enforcement
    omissions = {}
    omissions_file = bundle.root / "omissions.cbor"
    if omissions_file.exists():
        try:
            omissions = cbor2.loads(omissions_file.read_bytes())
        except Exception:
            pass
    if scope_check:
        if (man.get("scope") == "FULL" or omissions.get("scope") == "FULL") and any(
            o.get("kind") == "SEGMENT_RANGE" for o in omissions.get("omitted", [])
        ):
            rep.add(F.DEFECT, "V-701", "FULL scope declares segment omissions")
        gapped = False
        for s in segs:
            seg_path = bundle.root / "segments" / f"{s['seg_seq']:06d}.seg"
            if seg_path.exists():
                data = seg_path.read_bytes()
                off, end = SEGH_LEN, len(data) - SEGF_LEN
                while off + HDR_LEN <= end:
                    h = Header.parse(data, off)
                    if h.type == 0x0F01:
                        gapped = True
                        break
                    off += HDR_LEN + h.payload_len
        if omissions.get("chain_gaps_present") is not None and omissions.get("chain_gaps_present") != gapped:
            rep.add(F.DEFECT, "V-702", "chain_gaps_present contradicts scan")
        if man.get("scope") == "RANGE":
            for s in (segs[0], segs[-1]):
                seg_path = bundle.root / "segments" / f"{s['seg_seq']:06d}.seg"
                if seg_path.exists():
                    data = seg_path.read_bytes()
                    n = data.count(b"ARGF")
                    if n != s.get("expected_record_count", n):
                        rep.add(F.ANOMALY, "V-703", f"boundary segment {s['seg_seq']} not whole")

    # Phase 6 — Chain recomputation & Segment Parsing
    gaps = 0
    total_records = 0

    seg_index = {}
    parsed_segments = []
    all_local_tags = []  # list of (epoch, rec_seq, of_val_or_tag, tag_bytes)
    all_epochs = set()

    chain_prev = None
    prev_boot = None

    for s in segs:
        seg_path = bundle.root / "segments" / f"{s['seg_seq']:06d}.seg"
        if not seg_path.exists():
            rep.add(F.DEFECT, "V-601", f"segment missing from disk: {s['seg_seq']}")
            continue

        sh, records_data, footer_closing_hash = _parse_segment(seg_path, rep, s["seg_seq"])
        if sh is None:
            continue
        all_epochs.add(sh.epoch)
        parsed_segments.append(sh)

        headers = _walk_records(records_data, rep, s["seg_seq"])
        if len(headers) != s.get("expected_record_count", len(headers)):
            rep.add(F.ANOMALY, "V-203",
                    f"record count {len(headers)} != declared {s['expected_record_count']}",
                    seg_seq=s["seg_seq"])

        if chain_prev is None:
            if sh.seg_seq == 0:
                lid = man.get("ledger_id")
                if isinstance(lid, str):
                    try:
                        lid = bytes.fromhex(lid)
                    except Exception:
                        pass
                if lid is None or len(lid) != 32 or sh.prev_seg_hash != ledger_root(lid):
                    rep.add(F.DEFECT, "V-103", "ledger root mismatch", seg_seq=s["seg_seq"])
                prev = sh.prev_seg_hash
            else:
                prev = sh.prev_seg_hash
                if man.get("scope") == "RANGE":
                    if not any(a.get("seg_seq") == sh.seg_seq - 1 for a in anchors):
                        rep.add(F.INFO, "V-106",
                                "range start: prev_seg_hash taken on trust unless a before-anchor is present",
                                seg_seq=s["seg_seq"])
        else:
            if sh.prev_seg_hash != chain_prev:
                rep.add(F.DEFECT, "V-102", "segment prev hash discontinuity",
                        seg_seq=s["seg_seq"])
            if prev_boot is not None and sh.boot_id != prev_boot:
                rep.add(F.INFO, "V-105", "boot boundary", seg_seq=s["seg_seq"])
            prev = sh.prev_seg_hash
        prev_boot = sh.boot_id

        for h in headers:
            total_records += 1
            calc = _entry_hash(prev, h)
            if not h.payload_root or h.payload_root == b"\0" * 32:
                rep.add(F.DEFECT, "V-101", "empty payload_root",
                        seg_seq=s["seg_seq"], record_seq=h.seq)
            prev = calc

            off = records_data.find(h.encode())
            payload = []
            if off != -1:
                try:
                    payload = cbor2.loads(records_data[off + HDR_LEN: off + HDR_LEN + h.payload_len])
                except Exception:
                    pass
            seg_index[h.seq] = (s["seg_seq"], payload, h)

            t = f"0x{h.type:04X}"
            if t == "0x0F01":
                gaps += 1
                desc = "GAP class=K reason=RING_FULL"
                if off != -1:
                    try:
                        body = cbor2.loads(records_data[off + HDR_LEN: off + HDR_LEN + h.payload_len])
                        desc = f"GAP class={body.get('class', 'K')} count={body.get('count', 0)} reason={body.get('reason', 'UNKNOWN')}"
                    except Exception:
                        pass
                rep.add(F.NOTICE, "V-201", desc, seg_seq=s["seg_seq"], record_seq=h.seq)
            elif t == "0x0F03":
                rep.add(F.ANOMALY, "V-401", "producer stall without stop",
                        seg_seq=s["seg_seq"], record_seq=h.seq)
            elif t == "0x0103":
                rep.add(F.NOTICE, "V-301", "clock step",
                        seg_seq=s["seg_seq"], record_seq=h.seq)
            elif t == "0x0402" or (isinstance(payload, list) and any(e.get("type") == "TAG_KEY_ROTATE" for e in payload if isinstance(e, dict))):
                rep.add(F.NOTICE, "V-917", "TAG_KEY_ROTATE present, global links severed",
                        seg_seq=s["seg_seq"], record_seq=h.seq)

            # Check overflow flag/record
            if isinstance(payload, list) and any(e.get("overflow") for e in payload if isinstance(e, dict)):
                rep.add(F.NOTICE, "V-916", "TAG_OVERFLOW present, overflow demoted to local",
                        seg_seq=s["seg_seq"], record_seq=h.seq)

        if footer_closing_hash is not None and prev != footer_closing_hash:
            rep.add(F.DEFECT, "V-101",
                    f"entry_hash mismatch: computed {prev.hex()[:16]} != footer {footer_closing_hash.hex()[:16]}",
                    seg_seq=s["seg_seq"])

        chain_prev = prev

        # Phase 7c — Tag structure and binding
        tleaves, seen_of = _phase_7c(records_data, headers, sh, rep, s["seg_seq"])
        for seq, tl, entry in tleaves:
            if entry.get("scope") == SCOPE_LOCAL:
                val = entry.get("of")
                loc = seg_index.get(seq)
                if loc and val is not None:
                    p = loc[1]
                    target_item = next((e for e in p if isinstance(e, dict) and e.get("i") == val), None)
                    if target_item and "v" in target_item:
                        val = target_item["v"]
                all_local_tags.append((sh.epoch, seq, val, entry.get("v")))

    expected_total = man.get("expected_record_count")
    if expected_total is not None and total_records < expected_total:
        rep.add(F.ANOMALY, "V-203", f"record count {total_records} below declared total {expected_total}")

    # Phase 7a/b — Openings verification
    proof_dir = bundle.root / "proofs"
    opened = 0
    proof_files = sorted(proof_dir.glob("open-*.cbor")) if proof_dir.exists() else []
    for pf in proof_files:
        try:
            proof = cbor2.loads(pf.read_bytes())
        except Exception as e:
            rep.add(F.DEFECT, "V-812", f"opening file unparseable {pf.name}: {e}")
            continue
        seg = next((x for x in segs if x["seg_seq"] == proof["seg_seq"]), None)
        if seg is None:
            rep.add(F.DEFECT, "V-811", f"opening for unexported segment {pf.name}")
            continue
        seg_path = bundle.root / "segments" / f"{seg['seg_seq']:06d}.seg"
        if not seg_path.exists():
            continue
        _, records_data, _ = _parse_segment(seg_path, F.Report(), seg["seg_seq"])
        headers = _walk_records(records_data, F.Report(), seg["seg_seq"])
        h = next((x for x in headers if x.seq == proof["record_seq"]), None)
        if h is None:
            rep.add(F.DEFECT, "V-811", f"opening for missing record {pf.name}")
            continue
        if proof["field"] >= MAX_FIELDS:
            rep.add(F.DEFECT, "V-812", f"field index out of range {pf.name}")
            continue
        try:
            name = proof.get("name")
            if not name:
                off = records_data.find(h.encode())
                if off != -1:
                    try:
                        pld = cbor2.loads(records_data[off + HDR_LEN: off + HDR_LEN + h.payload_len])
                        for entry in pld:
                            if isinstance(entry, dict) and entry.get("i") == proof["field"]:
                                name = entry.get("name")
                                break
                    except Exception:
                        pass
            start = leaf(h.nonce, proof["field"], name or "", proof["value"], proof["salt"])
            if walk(proof["path"], proof["path_dirs"], start) != h.payload_root:
                rep.add(F.DEFECT, "V-811", f"opening root mismatch {pf.name}",
                        seg_seq=seg["seg_seq"], record_seq=h.seq)
            else:
                opened += 1
        except Exception as e:
            rep.add(F.DEFECT, "V-812", f"opening malformed {pf.name}: {e}")

    for spec in require_open:
        rec, fld = spec.split(":")
        found = False
        for pf in proof_files:
            try:
                p_cbor = cbor2.loads(pf.read_bytes())
                if p_cbor.get("record_seq") == int(rec) and p_cbor.get("field") == int(fld):
                    found = True
                    break
            except Exception:
                pass
        if not found:
            rep.add(F.DEFECT, "V-818", f"required opening absent: {spec}")

    # Phase 7d — Bridge verification
    bridged_pairs = _phase_7d(proof_dir, seg_index, rep)

    # Check for unbridged local tags across multi-epoch bundles
    if len(all_epochs) > 1 and all_local_tags:
        for idx1 in range(len(all_local_tags)):
            for idx2 in range(idx1 + 1, len(all_local_tags)):
                ep1, rec1, val1, tag1 = all_local_tags[idx1]
                ep2, rec2, val2, tag2 = all_local_tags[idx2]
                if ep1 != ep2 and val1 is not None and val1 == val2:
                    if (rec1, rec2) not in bridged_pairs and (rec2, rec1) not in bridged_pairs:
                        rep.add(F.ANOMALY, "V-918",
                                f"local tag in epoch {ep1} not bridged to epoch {ep2}",
                                record_seq=rec1)
                        rep.local_tags = True

    # Phase 8 — Grade
    if rep.count(F.FATAL) or rep.count(F.DEFECT):
        rep.grade = "INDETERMINATE"
    elif man.get("scope") == "CASE":
        rep.grade = "FILTERED"
    elif gaps:
        rep.grade = "GAPPED"
    elif producer_mode in (None, "degraded"):
        rep.grade = "GAPPED"
        rep.add(F.ANOMALY, "V-903",
                f"grade capped: no class K producer "
                f"({producer_mode or 'unknown'})")
    else:
        rep.grade = "SEALED"
    if producer_mode in (None, "degraded") and rep.grade != "GAPPED":
        rep.add(F.NOTICE, "V-903", f"no class K producer ({producer_mode})")

    if rep.local_tags:
        rep.grade = f"{rep.grade}+LOCAL_TAGS"

    rep.revealed_fraction = (opened / total_records) if total_records else 0.0
    if min_reveal is not None and rep.revealed_fraction < min_reveal:
        rep.add(F.NOTICE, "V-818",
                f"revealed fraction {rep.revealed_fraction:.3f} below minimum {min_reveal}")

    return rep
