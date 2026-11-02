"""What must keep working when the RPC, a sink, a Safe or a log misbehaves."""
import json

import pytest
import requests
from eth_abi import encode
from hexbytes import HexBytes
from web3 import Web3

from ownerwatch import alerts as alerts_mod, cli
from ownerwatch.alerts import Alert, Dispatcher, HeartbeatGate, redact
from ownerwatch.config import Alerts, Config, Contract, Safe, Token, Treasury, load_all
from ownerwatch.events import topic0
from ownerwatch.watcher import Watcher, build_watchers

ADDR = "0x" + "aB" * 20
ADDR = Web3.to_checksum_address(ADDR)
OTHER = Web3.to_checksum_address("0x" + "cd" * 20)
TX = "0x" + "11" * 32


class Eth:
    chain_id = 1

    def __init__(self, head=1000, logs=None, max_range=None, fail_logs=False):
        self.head, self.logs, self.max_range, self.fail_logs = head, logs or [], max_range, fail_logs
        self.balance_blocks, self.ranges = [], []
        self.balance = 10**21

    @property
    def block_number(self):
        return self.head

    def get_logs(self, params):
        self.ranges.append((params["fromBlock"], params["toBlock"]))
        if self.fail_logs:
            raise RuntimeError("logs down")
        if self.max_range and params["toBlock"] - params["fromBlock"] + 1 > self.max_range:
            raise ValueError("range too wide")
        return [lg for lg in self.logs if params["fromBlock"] <= lg["blockNumber"] <= params["toBlock"]]

    def get_balance(self, address, block_identifier=None):
        self.balance_blocks.append(block_identifier)
        return self.balance

    def get_block(self, n):
        return {"timestamp": 1_700_000_000}


class W3:
    def __init__(self, **kw):
        self.eth = Eth(**kw)


def cfg(tmp_path, **kw):
    kw.setdefault("contracts", [Contract(ADDR, "C")])
    kw.setdefault("confirmations", 0)
    return Config(rpc_url="http://x", start_block=kw.pop("start_block", 1), state_file=str(tmp_path / "s.json"), **kw)


def watcher(c, w3=None, **kw):
    got = []
    w = Watcher(c, Dispatcher(c.alerts, sinks=[got.append]), w3=w3 or W3(**kw))
    return w, got


def log(sig, topics=(), data=b"", block=5):
    return {"address": ADDR, "topics": [HexBytes(topic0(sig)), *map(HexBytes, topics)], "data": HexBytes(data), "blockNumber": block,
            "transactionHash": HexBytes(TX), "logIndex": 0, "transactionIndex": 0, "blockHash": HexBytes(b"\x00" * 32)}


def padded(a):
    return bytes.fromhex("00" * 12 + a[2:])


# ---- logs that do not match the catalog's layout ------------------------------------------------------------------

@pytest.mark.parametrize("sig,word,event", [
    ("AddedOwner(address)", OTHER, "AddedOwner"),
    ("RemovedOwner(address)", OTHER, "RemovedOwner"),
    ("EnabledModule(address)", OTHER, "EnabledModule"),
    ("DisabledModule(address)", OTHER, "DisabledModule"),
    ("ChangedGuard(address)", OTHER, "ChangedGuard"),
    ("ChangedFallbackHandler(address)", OTHER, "ChangedFallbackHandler"),
])
def test_safe_141_indexes_its_events_and_they_still_alert(tmp_path, sig, word, event):
    w, _ = watcher(cfg(tmp_path))
    a = w._decode_admin(log(sig, [padded(word)]))
    assert a.event == event and OTHER in a.message and "cannot decode" not in a.message


def test_safe_141_execution_events_decode(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    a = w._decode_admin(log("ExecutionSuccess(bytes32,uint256)", [b"\x22" * 32], encode(["uint256"], [0])))
    assert a.event == "ExecutionSuccess" and "22" * 32 in a.message


def test_old_proxy_upgraded_with_implementation_in_data(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    a = w._decode_admin(log("Upgraded(address)", [], encode(["address"], [OTHER])))
    assert a.event == "Upgraded" and a.severity == "critical" and OTHER in a.message


def test_invalid_utf8_in_a_proposal_cannot_hide_it(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    sig = "StartVote(uint256,address,string)"
    data = encode(["bytes"], [b"Vote \xff\xfe"])
    a = w._decode_admin(log(sig, [(1).to_bytes(32, "big"), padded(OTHER)], data))
    assert a.event == "StartVote" and "cannot decode" not in a.message


def test_a_catalog_log_that_will_not_decode_alerts_raw_at_its_severity(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    a = w._decode_admin(log("ChangedThreshold(uint256)", [b"\x01" * 32, b"\x02" * 32], b"\xab"))
    assert a.severity == "critical" and a.event == "ChangedThreshold"
    assert "cannot decode" in a.message and "ab" in a.message and a.tx_hash == TX


def test_unknown_topic_stays_silent(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    assert w._decode_admin(log("NotInTheCatalog(uint256)")) is None


def test_note_with_absurd_eta_still_alerts(tmp_path):
    from ownerwatch.events import NOTE_SPECS
    w, _ = watcher(cfg(tmp_path))
    t0, spec = next((t, s) for t, s in NOTE_SPECS.items() if "eta" in s.args)
    types = spec.signature[spec.signature.index("(") + 1:-1].split(",")
    values = [OTHER if t == "address" else (b"\x01" * 32 if t == "bytes32" else (2**255 if t == "uint256" else b"\x01")) for t in types]
    fax = bytes(HexBytes(topic0(spec.signature)))[:4] + encode(types, values)
    lg = log("x()", [], encode(["uint256", "bytes"], [0, fax]))
    lg["topics"] = [HexBytes(t0), *[HexBytes(b"\x00" * 32)] * 3]
    assert w._decode_admin(lg).event == spec.name


def test_empty_signature_timelock_call_is_decoded_from_the_calldata(tmp_path, monkeypatch):
    import ownerwatch.watcher as mod
    monkeypatch.setattr(mod, "describe_call", lambda d, *a: "setFee(1)")
    w, _ = watcher(cfg(tmp_path))
    data = encode(["address", "uint256", "string", "bytes", "uint256"], [OTHER, 0, "", b"\x12\x34\x56\x78", 1])
    a = w._decode_admin(log("QueueTransaction(bytes32,address,uint256,string,bytes,uint256)", [b"\x01" * 32, padded(OTHER)],
                            encode(["uint256", "string", "bytes", "uint256"], [0, "", b"\x12\x34\x56\x78", 1])))
    assert data and a.event == "QueueTransaction" and "setFee(1)" in a.message


def test_tuple_signature_keeps_its_arguments():
    from ownerwatch.decode import describe_signature_call
    data = encode(["(address,uint256)", "uint256"], [(OTHER, 5), 9])
    out = describe_signature_call("set((address,uint256),uint256)", data)
    assert "5" in out and "9" in out and out != "set((address,uint256),uint256)"


# ---- scanning -----------------------------------------------------------------------------------------------------

def test_capped_rpc_gets_through_a_backlog_and_saves_progress(tmp_path):
    c = cfg(tmp_path, max_block_range=2000)
    w, _ = watcher(c, head=2000, max_range=10)
    assert w.poll_once() == 0
    assert w.cursor.last_block == 2000
    assert w._chunk <= 10


def test_a_scan_failure_keeps_the_progress_already_made(tmp_path):
    c = cfg(tmp_path, max_block_range=100)
    w3 = W3(head=1000)
    w, _ = watcher(c, w3=w3)
    original = w3.eth.get_logs

    def flaky(params):
        if params["fromBlock"] > 300:
            raise RuntimeError("down")
        return original(params)

    w3.eth.get_logs = flaky
    with pytest.raises(RuntimeError):
        w.poll_once()
    assert 300 <= w.cursor.last_block < 1000


def test_chunk_grows_back_after_a_transient_failure(tmp_path):
    from ownerwatch.watcher import GROW_AFTER
    c = cfg(tmp_path, max_block_range=64)
    w, _ = watcher(c, head=5000)
    w._chunk = 1
    w.scan_range(1, GROW_AFTER * 8)
    assert w._chunk > 1


def test_failed_logs_do_not_skip_safes_or_native_and_the_failure_surfaces(tmp_path, monkeypatch):
    c = cfg(tmp_path, treasuries=[Treasury(OTHER, "T", [], [], 1.0)], safes=[Safe(OTHER, "S", "eth")])
    w, _ = watcher(c, head=100, fail_logs=True)
    polled = []
    monkeypatch.setattr(w.safe_queue, "poll", lambda: polled.append(1) or [])
    with pytest.raises(RuntimeError):
        w.poll_once()
    assert polled and w.w3.eth.balance_blocks == [100]


def test_native_only_treasury_reads_the_head_not_the_start_block(tmp_path):
    c = cfg(tmp_path, contracts=[], treasuries=[Treasury(OTHER, "T", [], [], 1.0)], start_block=123)
    w, got = watcher(c, head=1000)
    w.poll_once()
    w.w3.eth.head = 2000
    w.w3.eth.balance -= 5 * 10**18
    w.poll_once()
    assert w.w3.eth.balance_blocks == [1000, 2000]
    assert [a.event for a in got] == ["BalanceDrop"]


def test_latest_start_is_fixed_on_the_first_poll(tmp_path):
    c = cfg(tmp_path, start_block="latest")
    w, _ = watcher(c, head=100, fail_logs=True)
    with pytest.raises(RuntimeError):
        w.poll_once()
    assert w.cursor.last_block == 99
    w.w3.eth.fail_logs = False
    w.w3.eth.head = 150
    w.w3.eth.ranges.clear()
    w.poll_once()
    assert w.w3.eth.ranges[0][0] == 100


def test_cursor_write_leaves_no_temp_file_and_valid_json(tmp_path):
    w, _ = watcher(cfg(tmp_path))
    w.cursor.save(7)
    assert json.loads((tmp_path / "s.json").read_text())["last_block"] == 7
    assert list(tmp_path.glob("*.tmp")) == []


# ---- token decimals -----------------------------------------------------------------------------------------------

def transfer_log(token, value, frm):
    return {"address": token, "topics": [HexBytes(topic0("Transfer(address,address,uint256)")), HexBytes(padded(frm)), HexBytes(padded(ADDR))],
            "data": HexBytes(encode(["uint256"], [value])), "blockNumber": 5, "transactionHash": HexBytes(TX),
            "logIndex": 0, "transactionIndex": 0, "blockHash": HexBytes(b"\x00" * 32)}


def treasury_watcher(tmp_path, call):
    token = Token(OTHER, "USDC", None, 1000.0)
    c = cfg(tmp_path, contracts=[], treasuries=[Treasury(ADDR, "T", [token], [])])
    w3 = W3()
    w3.eth.call = call
    return watcher(c, w3=w3)[0]


def test_omitted_decimals_are_read_from_the_token(tmp_path):
    w = treasury_watcher(tmp_path, lambda tx: (6).to_bytes(32, "big"))
    a = w._decode_transfer(transfer_log(OTHER, 50_000_000 * 10**6, ADDR))
    assert a and "50,000,000.00" in a.message
    assert w._decode_transfer(transfer_log(OTHER, 999 * 10**6, ADDR)) is None


def test_unreadable_decimals_alert_rather_than_guess(tmp_path):
    def down(tx):
        raise RuntimeError("no")
    w = treasury_watcher(tmp_path, down)
    a = w._decode_transfer(transfer_log(OTHER, 5, ADDR))
    assert a and "5 base units" in a.message


# ---- Safe queues --------------------------------------------------------------------------------------------------

class SafeSession:
    def __init__(self, bad=()):
        self.bad, self.pending = set(bad), {}

    def get(self, url, params=None, headers=None, timeout=None):
        address = url.split("/safes/")[1].split("/")[0]
        if address in self.bad:
            raise RuntimeError("404")

        class R:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(_):
                if url.endswith("/multisig-transactions/"):
                    return {"results": self.pending.get(address, []), "next": None}
                return {"threshold": 2}
        return R()


def tx(h, confs=1):
    return {"safeTxHash": h, "nonce": 1, "to": OTHER, "value": "0", "data": None, "confirmations": [{}] * confs}


def test_one_failing_safe_does_not_silence_a_healthy_one(tmp_path, monkeypatch):
    good, bad = ADDR, OTHER
    c = cfg(tmp_path, contracts=[], safes=[Safe(good, "good", "eth"), Safe(bad, "bad", "eth")])
    w, got = watcher(c)
    w.safe_queue.session = SafeSession(bad=[bad])
    w._check_safes()                     # the healthy Safe is seeded; the other fails
    w.safe_queue.session.pending[good] = [tx("0xnew")]
    w._check_safes()
    assert [a.event for a in got] == ["SafeTxProposed"]


def test_same_safe_address_on_two_chains_keeps_separate_state(tmp_path):
    c = cfg(tmp_path, contracts=[], safes=[Safe(ADDR, "eth", "eth"), Safe(ADDR, "base", "base")])
    w, got = watcher(c)
    w.safe_queue.session = SafeSession()
    w.safe_queue.session.pending[ADDR] = [tx("0xa")]
    w._check_safes()
    assert got == []
    w._check_safes()
    assert got == []


def test_safe_state_from_before_chain_keys_is_kept(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"last_block": 1, "safes": {ADDR: {"seen": {"0xold": 1}, "ready": [], "seeded": True}}}))
    w, got = watcher(cfg(tmp_path, contracts=[], safes=[Safe(ADDR, "S", "eth")]))
    w.safe_queue.session = SafeSession()
    w.safe_queue.session.pending[ADDR] = [tx("0xold")]
    w._check_safes()
    assert got == []


def test_queued_transactions_already_seen_cost_no_decoding(tmp_path, monkeypatch):
    import ownerwatch.safe as mod
    calls = []
    monkeypatch.setattr(mod, "describe_call", lambda *a: calls.append(1) or "x")
    w, got = watcher(cfg(tmp_path, contracts=[], safes=[Safe(ADDR, "S", "eth")]))
    w.safe_queue.session = SafeSession()
    w.safe_queue.session.pending[ADDR] = [{**tx("0xa"), "data": "0x12345678"}]
    w._check_safes()
    w._check_safes()
    assert calls == []


# ---- delivery -----------------------------------------------------------------------------------------------------

class Resp:
    def __init__(self, status=200, headers=None):
        self.status_code, self.headers = status, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(f"{self.status_code} for url: https://hook.example/secret-token")
            e.response = self
            raise e


def alert(n=1, severity="high"):
    return Alert(severity, "ethereum", ADDR, "L", "Upgraded", "ERC-1967", f"m{n}", n, TX)


def test_failed_delivery_is_retried_and_survives_a_restart(tmp_path, monkeypatch):
    posted, status = [], [503]
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: (posted.append(kw["json"]), Resp(status[0]))[1])
    c = cfg(tmp_path, alerts=Alerts(slack_webhook="https://hook.example/x"))
    w, _ = watcher(c, head=10)
    w.dispatcher.send(alert(1))
    w.dispatcher.send(alert(2))
    assert [i["alert"]["message"] for i in w.dispatcher.outbox] == ["m1", "m2"]
    w._save()
    posted.clear()
    status[0] = 200
    w2, _ = watcher(c, head=10)      # a new process reads the outbox from the state file
    w2.poll_once()
    assert ["m1" in p["text"] for p in posted][:1] == [True] and any("m2" in p["text"] for p in posted)
    assert w2.dispatcher.outbox == []


def test_retry_keeps_order_behind_a_failing_sink(monkeypatch):
    seen, status = [], [503]
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: (seen.append(kw["json"]["text"]), Resp(status[0]))[1])
    d = Dispatcher(Alerts(slack_webhook="https://s"))
    d.send(alert(1))
    seen.clear()
    d.send(alert(2))
    assert seen == []                # queued behind m1, not sent ahead of it
    status[0] = 200
    d.flush()
    assert ["m1" in seen[0], "m2" in seen[1]] == [True, True]


def test_a_payload_the_sink_refuses_does_not_block_the_rest(monkeypatch):
    seen = []

    def post(url, **kw):
        text = kw["json"]["text"]
        seen.append(text)
        return Resp(400 if "m1" in text else 200)

    monkeypatch.setattr(alerts_mod.requests, "post", post)
    d = Dispatcher(Alerts(slack_webhook="https://s"))
    d.outbox = [{"sink": "slack", "alert": alert(1).__dict__}, {"sink": "slack", "alert": alert(2).__dict__}]
    d.flush()
    assert d.outbox == [] and any("m2" in t for t in seen)


def test_outbox_is_bounded(monkeypatch):
    monkeypatch.setattr(alerts_mod, "OUTBOX_MAX", 3)
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: Resp(500))
    d = Dispatcher(Alerts(slack_webhook="https://s"))
    for i in range(5):
        d.send(alert(i))
    assert [i["alert"]["message"] for i in d.outbox] == ["m2", "m3", "m4"]


def test_429_waits_for_retry_after(monkeypatch):
    waits, answers = [], [Resp(429, {"Retry-After": "7"}), Resp(200)]
    monkeypatch.setattr(alerts_mod.time, "sleep", waits.append)
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: answers.pop(0))
    assert Dispatcher(Alerts(slack_webhook="https://s")).send(alert()) is True
    assert waits == [7.0]


def test_secrets_never_reach_the_log(monkeypatch, caplog):
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: Resp(500))
    with caplog.at_level("WARNING", logger="ownerwatch"):
        Dispatcher(Alerts(slack_webhook="https://hook.example/secret-token")).send(alert())
    assert "secret-token" not in caplog.text and "hook.example" in caplog.text
    assert "SECRET" not in redact("HTTPSConnectionPool(host='a.com', port=443): Max retries exceeded with url: /v2/SECRET (Caused by x)")
    assert "SECRET" not in redact("https://user:SECRET@rpc.example/v2/SECRET?key=SECRET")


def test_clipping_keeps_block_and_transaction():
    a = Alert("high", "c", ADDR, "L", "E", "S", "x" * 5000, 42, TX)
    t = a.text(4096)
    assert len(t) <= 4096 and "block 42" in t and TX in t


def test_slack_escapes_on_chain_text(monkeypatch):
    sent = []
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: (sent.append(kw["json"]["text"]), Resp())[1])
    a = Alert("high", "c", ADDR, "L", "E", "S", "<https://evil.example|click> & <!channel>", 1, TX)
    Dispatcher(Alerts(slack_webhook="https://s")).send(a)
    assert "<https" not in sent[0] and "<!channel" not in sent[0] and "&lt;https" in sent[0]


def test_ascii_stdout_does_not_lose_the_alert(monkeypatch, capfd):
    import io
    import sys
    out = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
    monkeypatch.setattr(sys, "stdout", out)
    got = []
    assert Dispatcher(Alerts(), sinks=[got.append]).send(Alert("high", "c", ADDR, "L", "E", "S", "café �", 1, TX)) is True
    assert got


def test_digest_and_forced_alerts_ignore_min_severity(monkeypatch):
    sent = []
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: (sent.append(1), Resp())[1])
    d = Dispatcher(Alerts(slack_webhook="https://s", daily_digest=True, min_severity="critical"))
    d.maybe_digest("c", 1, today="2026-10-14")
    assert d.maybe_digest("c", 2, today="2026-10-15") is True
    assert sent == [1]


# ---- heartbeat ----------------------------------------------------------------------------------------------------

def pings(monkeypatch):
    out = []
    monkeypatch.setattr(alerts_mod.requests, "get", lambda url, timeout=None: out.append(url))
    return out


def test_no_heartbeat_when_logs_fail(tmp_path, monkeypatch):
    out = pings(monkeypatch)
    w, _ = watcher(cfg(tmp_path, alerts=Alerts(heartbeat_url="https://hc")), fail_logs=True)
    with pytest.raises(RuntimeError):
        w.poll_once()
    assert out == []


def test_no_heartbeat_when_every_safe_poll_fails(tmp_path, monkeypatch):
    out = pings(monkeypatch)
    w, _ = watcher(cfg(tmp_path, contracts=[], safes=[Safe(ADDR, "S", "eth")], alerts=Alerts(heartbeat_url="https://hc")))
    w.safe_queue.session = SafeSession(bad=[ADDR])
    w.poll_once()
    assert out == []


def test_no_heartbeat_while_alerts_wait_for_delivery(tmp_path, monkeypatch):
    out = pings(monkeypatch)
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: Resp(500))
    w, _ = watcher(cfg(tmp_path, alerts=Alerts(heartbeat_url="https://hc", slack_webhook="https://s")))
    w.dispatcher.send(alert())
    w.poll_once()
    assert out == []


def test_heartbeat_on_a_healthy_poll(tmp_path, monkeypatch):
    out = pings(monkeypatch)
    w, _ = watcher(cfg(tmp_path, alerts=Alerts(heartbeat_url="https://hc")))
    w.poll_once()
    assert out == ["https://hc"]


def test_shared_heartbeat_needs_every_chain():
    gate = HeartbeatGate({"a", "b"})
    assert gate.ready("a") is False and gate.ready("a") is False
    assert gate.ready("b") is True
    assert gate.ready("a") is False


def test_build_watchers_gates_a_shared_url(tmp_path, monkeypatch):
    path = tmp_path / "c.yaml"
    path.write_text(f"""
alerts: {{heartbeat_url: "https://hc"}}
chains:
  - {{rpc_url: "http://a.invalid", chain_name: a, state_file: {tmp_path}/a.json, contracts: [{{address: "{ADDR}"}}]}}
  - {{rpc_url: "http://b.invalid", chain_name: b, state_file: {tmp_path}/b.json, contracts: [{{address: "{ADDR}"}}]}}
""")
    ws = build_watchers(load_all(path))
    assert ws[0].dispatcher.heartbeat_gate is ws[1].dispatcher.heartbeat_gate is not None


# ---- config -------------------------------------------------------------------------------------------------------

def write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return p


BASE = f'rpc_url: "http://x"\ncontracts: [{{address: "{ADDR}"}}]\n'


@pytest.mark.parametrize("extra,word", [
    ("alerts: {discord_webhok: x}", "discord_webhok"),
    ("confirmatons: 2", "confirmatons"),
    ("alerts: {min_severity: HIGH}", "min_severity"),
    ("start_block: earliest", "start_block"),
    ("max_block_range: 0", "max_block_range"),
    ("confirmations: -5", "confirmations"),
    ("poll_interval_seconds: 0", "poll_interval_seconds"),
    ("alerts: {telegram_bot_token: x}", "telegram"),
    (f'treasuries: [{{address: "{OTHER}", min_native_drop: 0}}]', "min_native_drop"),
])
def test_bad_config_is_rejected(tmp_path, extra, word):
    with pytest.raises(ValueError, match=word):
        load_all(write(tmp_path, BASE + extra + "\n"))


def test_two_unnamed_chains_cannot_share_state(tmp_path):
    text = f'chains:\n  - {{rpc_url: "http://a", contracts: [{{address: "{ADDR}"}}]}}\n  - {{rpc_url: "http://b", contracts: [{{address: "{ADDR}"}}]}}\n'
    with pytest.raises(ValueError, match="share"):
        load_all(write(tmp_path, text))


def test_safe_chain_defaults_to_the_configs_chain(tmp_path):
    text = f'rpc_url: "http://x"\nchain_name: base\nsafes: [{{address: "{ADDR}"}}]\n'
    assert load_all(write(tmp_path, text))[0].safes[0].chain == "base"
    text = f'rpc_url: "http://x"\nchain_name: mychain\nsafes: [{{address: "{ADDR}"}}]\n'
    with pytest.raises(ValueError, match="chain:"):
        load_all(write(tmp_path, text))


def test_old_matic_key_maps_to_the_live_one(tmp_path):
    text = f'rpc_url: "http://x"\nchain_name: polygon\nsafes: [{{address: "{ADDR}", chain: matic}}]\n'
    assert load_all(write(tmp_path, text))[0].safes[0].chain == "pol"


def test_missing_decimals_stays_unknown(tmp_path):
    text = f'rpc_url: "http://x"\ntreasuries: [{{address: "{ADDR}", tokens: [{{address: "{OTHER}"}}]}}]\n'
    assert load_all(write(tmp_path, text))[0].treasuries[0].tokens[0].decimals is None


# ---- CLI ----------------------------------------------------------------------------------------------------------

def two_chains(tmp_path):
    return write(tmp_path, f"""
chains:
  - {{rpc_url: "http://127.0.0.1:1", chain_name: dead, state_file: {tmp_path}/dead.json, contracts: [{{address: "{ADDR}"}}]}}
  - {{rpc_url: "http://127.0.0.1:2", chain_name: live, state_file: {tmp_path}/live.json, contracts: [{{address: "{ADDR}"}}]}}
""")


def test_once_polls_every_chain_and_reports_the_dead_one(tmp_path, monkeypatch, capsys):
    polled = []

    class FakeW:
        def __init__(self, cfg):
            self.cfg = cfg

        def poll_once(self):
            polled.append(self.cfg.chain_name)
            if self.cfg.chain_name == "dead":
                raise RuntimeError("down https://rpc.example/v2/SECRET")
            return 0

    monkeypatch.setattr(cli, "build_watchers", lambda cfgs: [FakeW(c) for c in cfgs])
    assert cli.main(["run", "--once", "--config", str(two_chains(tmp_path))]) == 1
    assert polled == ["dead", "live"]
    err = capsys.readouterr().err
    assert "dead" in err and "SECRET" not in err


def test_backfill_never_posts_to_remote_sinks(tmp_path, monkeypatch):
    posted = []
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: posted.append(url))
    captured = {}

    class FakeWatcher:
        def __init__(self, cfg, dispatcher):
            captured["d"] = dispatcher

        def scan_range(self, a, b):
            captured["d"].send(alert())
            return 1

    monkeypatch.setattr(cli, "Watcher", FakeWatcher)
    jsonl = tmp_path / "a.jsonl"
    p = write(tmp_path, BASE + f'alerts: {{slack_webhook: "https://s", webhook_url: "https://w", jsonl_path: "{jsonl}"}}\n')
    assert cli.main(["backfill", "--config", str(p), "--from-block", "1", "--to-block", "2"]) == 0
    assert posted == [] and jsonl.exists()


def test_test_alert_fails_on_a_dead_sink_and_ignores_min_severity(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts_mod.requests, "post", lambda url, **kw: (calls.append(url), Resp(500))[1])
    p = write(tmp_path, BASE + 'alerts: {slack_webhook: "https://s", min_severity: critical}\n')
    assert cli.main(["test-alert", "--config", str(p)]) == 1
    assert calls == ["https://s"]


def test_python_m_exit_code_is_passed_on():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "ownerwatch", "validate", "--config", "/nonexistent.yaml"], capture_output=True)
    assert r.returncode == 2
