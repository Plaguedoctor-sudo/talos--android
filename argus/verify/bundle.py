from __future__ import annotations
import pathlib, tarfile, tempfile
import cbor2
from blake3 import blake3

REQUIRED = ("cover.txt", "omissions.cbor", "attestation.cbor",
            "redactions.cbor", "selfverify.cbor")


class BundleError(Exception):
    pass


class Bundle:
    def __init__(self, root, tmp=None, orig_path=None):
        self.root, self._tmp = pathlib.Path(root), tmp
        self.orig_path = pathlib.Path(orig_path) if orig_path else self.root
        raw = (self.root / "manifest.cbor").read_bytes()
        try:
            self.manifest = cbor2.loads(raw)
        except Exception as e:
            raise BundleError(f"manifest unparseable: {e}")
        if cbor2.dumps(self.manifest, canonical=True) != raw:
            raise BundleError("manifest non-canonical")
        if self.manifest.get("argx_version") != 1:
            raise BundleError("unsupported argx_version")
        self.manifest_hash = blake3(raw).digest()

    @classmethod
    def open(cls, path):
        path = pathlib.Path(path)
        if path.is_dir():
            return cls(path, orig_path=path)
        tmp = tempfile.TemporaryDirectory(prefix="argx-")
        with tarfile.open(path) as tf:
            tf.extractall(tmp.name, filter="data")
        return cls(pathlib.Path(tmp.name), tmp, orig_path=path)

    def close(self):
        if self._tmp:
            self._tmp.cleanup()

    def all_files(self):
        return sorted(p.relative_to(self.root).as_posix()
                      for p in self.root.rglob("*") if p.is_file())

    def check_integrity(self, rep):
        declared = {e["path"]: e for e in self.manifest.get("files", [])}
        actual = set(self.all_files()) - {"manifest.cbor", "bundle.sig"}
        for p in sorted(actual - set(declared)):
            rep.add(40, "V-603", f"unmanifested file: {p}")
        for p, e in sorted(declared.items()):
            fp = self.root / p
            if not fp.is_file():
                rep.add(40, "V-601", f"missing file: {p}")
                continue
            d = fp.read_bytes()
            if len(d) != e["size"] or blake3(d).digest() != e["blake3"]:
                rep.add(40, "V-601", f"hash mismatch: {p}")
        for r in REQUIRED:
            if r not in declared:
                rep.add(40, "V-601", f"required file unmanifested: {r}")
        return rep.count(40) == 0
