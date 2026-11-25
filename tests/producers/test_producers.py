from argus.argf2.producers.ring import Ring
from argus.argf2.producers.watchdog import Watchdog
from argus.argf2.producers.drain import Drainer
from argus.argf2.producers.capability import Capabilities
from argus.argf2.producers import enrich


def test_class_reservation_protects_kernel():
    r = Ring(capacity=100)
    for _ in range(60):
        r.push(0x41, ("X", {}))        # flood app class
    assert r.push(0x4B, ("EXEC", {}))  # kernel still admitted
    assert r.dropped[0x41] > 0


def test_gap_counter_sticky_and_drained():
    r = Ring(capacity=10)
    for _ in range(50):
        r.push(0x4B, ("EXEC", {}))
    assert r.dropped[0x4B] > 0
    g = r.take_gaps()
    assert 0x4B in g
    assert r.take_gaps() == {}


def test_enrich_degrades_on_missing_pid():
    assert enrich.cgroup_id(999999) == 0
    assert enrich.ids(999999) == (0, 0)
    assert enrich.comm(999999) == "?"


def test_path_hash_stable():
    assert enrich.path_hash("/usr/bin/lrd-sensor") == \
           enrich.path_hash("/usr/bin/lrd-sensor")


def test_watchdog_fires_once():
    class W:
        n = 0
        def lifecycle(self, t, pid): W.n += 1
    class P:
        producer_id = 1
    w = Watchdog(W(), [P()])
    w.last[1] -= 31
    w.check(); w.check()
    assert W.n == 1


def test_drainer_processes_ring_and_gaps():
    class MockWriter:
        def __init__(self):
            self.records = []
        def write(self, record, cls=None, uid=0, gid=0, cgroup_id=0):
            self.records.append((record, cls, uid, gid, cgroup_id))

    r = Ring(capacity=10)
    # Flood to trigger a gap in class 0x4B
    for _ in range(15):
        r.push(0x4B, ("EXEC", {"path": "/bin/true", "pid": 1}))

    writer = MockWriter()
    drainer = Drainer(ring=r, writer=writer)
    n, k_gaps = drainer.tick()
    assert n > 0
    assert k_gaps > 0
    # The first record must be the 0x0F01 GAP record
    gap_record, gap_cls, _, _, _ = writer.records[0]
    assert gap_cls == 0x4B
    assert gap_record.type == 0x0F01

    # Following records must be 0x0801 EXEC records
    exec_record, exec_cls, _, _, _ = writer.records[1]
    assert exec_cls == 0x4B
    assert exec_record.type == 0x0801


def test_capabilities_mode():
    caps = Capabilities()
    mode = caps.mode()
    assert mode in ("audit", "bpf", "degraded")
