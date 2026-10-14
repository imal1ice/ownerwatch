from ownerwatch.safe import SafeQueueWatcher, SafeTarget


class FakeResp:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self):
        self.pending = []
        self.threshold = 2

    def get(self, url, params=None, headers=None, timeout=None):
        if url.endswith("/multisig-transactions/"):
            return FakeResp({"results": self.pending, "next": None})
        return FakeResp({"threshold": self.threshold, "owners": ["0xa", "0xb", "0xc"]})


def _tx(h, confs, data="0x", nonce=1):
    return {"safeTxHash": h, "nonce": nonce, "to": "0x" + "11" * 20, "value": "1000000000000000000",
            "data": data, "proposer": "0x" + "aa" * 20, "confirmations": [{"owner": f"0x{i}"} for i in range(confs)]}


def test_queue_lifecycle(monkeypatch):
    import ownerwatch.safe as mod
    monkeypatch.setattr(mod, "describe_call", lambda d, *a: "addOwnerWithThreshold(address,uint256) [0x0d582f13]")
    sess = FakeSession()
    w = SafeQueueWatcher([SafeTarget("0x" + "ff" * 20, "Admin Safe", "eth")], "ethereum", session=sess)

    # first run: existing queue is recorded silently
    sess.pending = [_tx("0xh1", 1)]
    assert w.poll(first_run=True) == []

    # a new proposal appears
    sess.pending = [_tx("0xh1", 1), _tx("0xh2", 1, data="0x0d582f13", nonce=2)]
    alerts = w.poll()
    assert [a.event for a in alerts] == ["SafeTxProposed"]
    assert "addOwnerWithThreshold" in alerts[0].message and "1/2 signatures" in alerts[0].message
    assert alerts[0].severity == "high"

    # h2 reaches threshold -> executable, reported once
    sess.pending = [_tx("0xh1", 1), _tx("0xh2", 2, data="0x0d582f13", nonce=2)]
    alerts = w.poll()
    assert [a.event for a in alerts] == ["SafeTxExecutable"]
    assert alerts[0].severity == "critical"
    assert w.poll() == []

    # state round-trips through export/import and forgets executed txs
    exported = w.export_state()
    w2 = SafeQueueWatcher([SafeTarget("0x" + "ff" * 20, "Admin Safe", "eth")], "ethereum", session=sess)
    w2.import_state(exported)
    sess.pending = [_tx("0xh1", 1)]
    assert w2.poll() == []
    assert "0xh2" not in w2.state["0x" + "ff" * 20].seen


def test_first_run_suppression_survives_failed_poll(monkeypatch):
    import ownerwatch.safe as mod
    monkeypatch.setattr(mod, "describe_call", lambda d, *a: "x")

    class Flaky(FakeSession):
        def __init__(self):
            super().__init__()
            self.fail = True

        def get(self, url, params=None, headers=None, timeout=None):
            if self.fail:
                raise RuntimeError("503")
            return super().get(url, params, headers, timeout)

    sess = Flaky()
    sess.pending = [_tx("0xold", 1)]
    w = SafeQueueWatcher([SafeTarget("0x" + "ff" * 20, "S", "eth")], "ethereum", session=sess)
    assert w.poll(first_run=True) == [] and w.last_poll_ok is False
    sess.fail = False
    # the watcher keeps first_run=True until a poll succeeds, so the old tx is still silent
    assert w.poll(first_run=True) == [] and w.last_poll_ok is True
    assert w.poll(first_run=False) == []


def test_pagination(monkeypatch):
    import ownerwatch.safe as mod
    monkeypatch.setattr(mod, "describe_call", lambda d, *a: "x")

    class Paged(FakeSession):
        def get(self, url, params=None, headers=None, timeout=None):
            if "page2" in url:
                return FakeResp({"results": [_tx("0xp2", 1)], "next": None})
            if url.endswith("/multisig-transactions/"):
                return FakeResp({"results": [_tx("0xp1", 1)], "next": url + "?page2"})
            return FakeResp({"threshold": 2})

    w = SafeQueueWatcher([SafeTarget("0x" + "ff" * 20, "S", "eth")], "ethereum", session=Paged())
    w.poll(first_run=True)
    assert set(w.state["0x" + "ff" * 20].seen) == {"0xp1", "0xp2"}


def test_safe_added_later_is_seeded_silently(monkeypatch):
    import ownerwatch.safe as mod
    monkeypatch.setattr(mod, "describe_call", lambda d, *a: "x")
    sess = FakeSession()
    sess.pending = [_tx("0xold1", 1), _tx("0xold2", 1)]
    a, b = "0x" + "aa" * 20, "0x" + "bb" * 20
    w1 = SafeQueueWatcher([SafeTarget(a, "A", "eth")], "ethereum", session=sess)
    w1.poll(first_run=True)
    exported = w1.export_state()           # only A is in the state file
    w2 = SafeQueueWatcher([SafeTarget(a, "A", "eth"), SafeTarget(b, "B", "eth")], "ethereum", session=sess)
    w2.import_state(exported)
    assert w2.poll(first_run=False) == []  # B's backlog is recorded, not alerted
    sess.pending = [_tx("0xold1", 1), _tx("0xold2", 1), _tx("0xnew", 1)]
    alerts = w2.poll()
    assert [(x.label, x.event) for x in alerts] == [("A", "SafeTxProposed"), ("B", "SafeTxProposed")]
    # legacy state without the seeded flag is treated as seeded
    w3 = SafeQueueWatcher([SafeTarget(a, "A", "eth")], "ethereum", session=sess)
    w3.import_state({a: {"seen": {"0xold1": 1}, "ready": []}})
    assert w3.state[a].seeded is True
