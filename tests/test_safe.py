from ownerwatch.safe import SafeQueueWatcher, SafeTarget


class FakeResp:
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
            return FakeResp({"results": self.pending})
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
