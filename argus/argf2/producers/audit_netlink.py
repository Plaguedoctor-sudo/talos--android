"""Class K producer: NETLINK_AUDIT consumer for execve/execveat and connect.

Kernel-version dependent: record type ids and the presence of EXECVE vs a
SYSCALL+EXECVE pair vary. The parser is table-driven so a new kernel is a
table edit, not a rewrite. ENOBUFS increments the class K gap counter.
"""
from __future__ import annotations
import socket, struct, errno

NETLINK_AUDIT = 9
AUDIT_SYSCALL = 1300
AUDIT_SOCKADDR = 1306
AUDIT_EXECVE = 1309
AUDIT_EOE = 1320
AUDIT_GET = 1000
AUDIT_SET = 1001

NLMSG_HDR = struct.Struct("<IHHII")


class AuditUnavailable(RuntimeError):
    pass


def _parse_kv(body: bytes) -> dict:
    out = {}
    for tok in body.decode("utf-8", "replace").split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            out.setdefault(k, v)
    return out


class AuditProducer:
    producer_id = 0x01
    cls = 0x4B

    def __init__(self, ring, sink=None):
        self.ring, self.sink = ring, sink
        self.sock = None
        self.pending = {}
        self.running = False

    def attach(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                                      NETLINK_AUDIT)
            self.sock.bind((0, 0))
        except (PermissionError, OSError) as e:
            raise AuditUnavailable(f"NETLINK_AUDIT bind failed: {e}")

    def _recv(self):
        try:
            data = self.sock.recv(65535)
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                self.ring.dropped[self.cls] = self.ring.dropped.get(self.cls, 0) + 1
                return
            raise
        off = 0
        while off + NLMSG_HDR.size <= len(data):
            ln, typ, _flags, _seq, _pid = NLMSG_HDR.unpack_from(data, off)
            body = data[off + NLMSG_HDR.size: off + ln]
            off += (ln + 3) & ~3
            self._handle(typ, body)

    def _handle(self, typ: int, body: bytes) -> None:
        if typ == AUDIT_SYSCALL:
            kv = _parse_kv(body)
            serial = kv.get("msg") or kv.get("serial")
            if kv.get("exe"):
                self.pending[serial] = {"exe": kv["exe"], "pid": int(kv.get("pid", 0))}
        elif typ == AUDIT_EXECVE:
            kv = _parse_kv(body)
            serial = kv.get("msg") or kv.get("serial")
            base = self.pending.pop(serial, {})
            self.ring.push(self.cls, ("EXEC", {
                "path": kv.get("exe") or base.get("exe") or "",
                "pid": base.get("pid", int(kv.get("pid", 0))),
            }))
        elif typ == AUDIT_SOCKADDR:
            kv = _parse_kv(body)
            serial = kv.get("msg") or kv.get("serial")
            base = self.pending.pop(serial, {})
            self.ring.push(self.cls, ("FLOW_OPEN", {
                "saddr": kv.get("saddr", ""),
                "pid": base.get("pid", int(kv.get("pid", 0))),
            }))

    def run(self) -> None:
        self.running = True
        self.attach()
        while self.running:
            self._recv()

    def stop(self) -> None:
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
