import pytest
from hexbytes import HexBytes

from ownerwatch.alerts import Dispatcher
from ownerwatch.config import Config, Contract, _build, _custom_events
from ownerwatch.events import _norm, topic0
from ownerwatch.watcher import Watcher

ADDR = "0x546329A16DcEdC46e93F7b03A65F49A84700bca1"
HOLDER = "0x04041e8781833aE6f080Ac57537fa609f7e9D413"
TX = b"\x11" * 32
LIMITS = "0x2fb09e307af03d6433da7437d1b14ef707fd08bafbda7722932bcdbc885d5bb4"
BURN_SIG = "ForceBurned(address,uint256)"


class Eth:
    chain_id = 1
    block_number = 100

    def __init__(self, logs=()):
        self.logs, self.filters = list(logs), []

    def get_logs(self, params):
        self.filters.append(params)
        return [lg for lg in self.logs if params["fromBlock"] <= lg["blockNumber"] <= params["toBlock"]
                and _hex_topic(lg) in params["topics"][0]]

    def get_block(self, n):
        return {"timestamp": 1_700_000_000}


class W3:
    def __init__(self, logs=()):
        self.eth = Eth(logs)


def _hex_topic(lg):
    return "0x" + bytes(lg["topics"][0]).hex()


def log(t0, topics=(), data=b""):
    return {"address": ADDR, "topics": [HexBytes(t0), *map(HexBytes, topics)], "data": HexBytes(data),
            "blockNumber": 5, "transactionHash": HexBytes(TX), "logIndex": 0, "transactionIndex": 0,
            "blockHash": HexBytes(b"\x00" * 32)}


def word(n):
    return n.to_bytes(32, "big")


def padded(a):
    return bytes.fromhex("00" * 12 + a[2:])


def make(tmp_path, entries, logs=()):
    got = []
    cfg = Config(rpc_url="http://x", start_block=1, confirmations=0, state_file=str(tmp_path / "s.json"),
                 contracts=[Contract(ADDR, "Vault")], custom_events=_custom_events(entries))
    return Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=W3(logs)), got


def test_signature_is_canonical_and_defaults_to_high():
    e = _custom_events([{"event": "event ForceBurned(address indexed account, uint amount);"}])[0]
    assert e.name == "ForceBurned" and e.severity == "high"
    assert e.topic0 == _norm(topic0("ForceBurned(address,uint256)"))
    assert e.abi["inputs"] == [{"name": "account", "type": "address", "indexed": True},
                               {"name": "amount", "type": "uint256", "indexed": False}]


def test_unnamed_arguments_get_positional_names():
    e = _custom_events([{"event": "Set(bytes32 indexed, address[] )"}])[0]
    assert [i["name"] for i in e.abi["inputs"]] == ["arg0", "arg1"]
    assert e.topic0 == _norm(topic0("Set(bytes32,address[])"))


@pytest.mark.parametrize("entry, needle", [
    ({"event": "Bad"}, "write it like"),
    ({"event": "Fees((uint256,uint256) a)"}, "tuples"),
    ({"event": "Foo(notatype x)"}, "cannot read"),
    ({"event": "Foo(uint256 a b)"}, "cannot read"),
    ({"event": "Foo(uint indexed a, uint indexed b, uint indexed c, uint indexed d)"}, "at most 3"),
    ({"event": "Foo()", "topic0": LIMITS, "name": "X"}, "either"),
    ({"name": "X"}, "either"),
    ({"event": "Foo()", "name": "X"}, "name:"),
    ({"topic0": "0x12", "name": "X"}, "64 hex"),
    ({"topic0": LIMITS}, "add name"),
    ({"event": "Foo()", "severity": "loud"}, "severity"),
    ({"event": "Foo()", "colour": "red"}, "unknown key"),
    ({"event": "OwnershipTransferred(address indexed a, address indexed b)"}, "built-in catalog"),
])
def test_bad_entries_fail_loudly(entry, needle):
    with pytest.raises(ValueError, match=needle):
        _custom_events([entry])


def test_duplicates_and_too_many_fail():
    with pytest.raises(ValueError, match="twice"):
        _custom_events([{"event": "Foo()"}, {"event": "Foo()"}])
    with pytest.raises(ValueError, match="at most"):
        _custom_events([{"event": f"Foo{i}()"} for i in range(51)])


def test_config_key_is_read_and_shared_across_chains(tmp_path):
    cfg = _build({"rpc_url": "http://x", "contracts": [{"address": ADDR}], "custom_events": [{"event": "Foo()"}]})
    assert [e.name for e in cfg.custom_events] == ["Foo"]
    from ownerwatch.config import load_all
    f = tmp_path / "c.yaml"
    f.write_text(f"""
custom_events:
  - event: "Foo()"
chains:
  - {{chain_name: a, rpc_url: "http://a", contracts: [{{address: "{ADDR}"}}]}}
  - {{chain_name: b, rpc_url: "http://b", contracts: [{{address: "{ADDR}"}}]}}
""")
    assert [[e.name for e in c.custom_events] for c in load_all(f)] == [["Foo"], ["Foo"]]


def test_decoded_custom_event_alerts_at_its_severity(tmp_path):
    lg = log(topic0(BURN_SIG), [padded(HOLDER)], word(7))
    w, got = make(tmp_path, [{"event": "ForceBurned(address indexed account, uint256 amount)", "severity": "critical"}], [lg])
    assert w._scan(1, 10) == 1
    a = got[0]
    assert (a.event, a.severity, a.source, a.label) == ("ForceBurned", "critical", "custom", "Vault")
    assert a.message == f"account={HOLDER}, amount=7"


def test_topic0_only_event_alerts_raw(tmp_path):
    lg = log(LIMITS, data=word(1) + word(2))
    w, got = make(tmp_path, [{"topic0": LIMITS, "name": "LimitsUpdated"}], [lg])
    assert w._scan(1, 10) == 1
    assert got[0].event == "LimitsUpdated" and got[0].severity == "high"
    assert "indexed: none" in got[0].message and (word(1) + word(2)).hex() in got[0].message


def test_wrong_declared_layout_still_alerts(tmp_path):
    # declared with an indexed argument, but the contract leaves everything in the data
    lg = log(topic0(BURN_SIG), data=word(7))
    w, got = make(tmp_path, [{"event": "ForceBurned(address indexed account, uint256 amount)"}], [lg])
    assert w._scan(1, 10) == 1
    assert "layout differs" in got[0].message and word(7).hex() in got[0].message


def test_config_text_never_reaches_str_format(tmp_path):
    lg = log(LIMITS)
    w, got = make(tmp_path, [{"topic0": LIMITS, "name": "{0.__class__}"}], [lg])
    assert w._scan(1, 10) == 1
    assert got[0].event == "{0.__class__}" and "__class__" not in got[0].message


def test_filter_gains_the_custom_topic_and_keeps_the_catalog(tmp_path):
    w, _ = make(tmp_path, [{"topic0": LIMITS, "name": "L"}])
    w._scan(1, 10)
    sent = w.w3.eth.filters[0]["topics"][0]
    assert LIMITS in sent and _norm(topic0("OwnershipTransferred(address,address)")) in sent


def test_catalog_events_are_untouched(tmp_path):
    lg = log(topic0("OwnershipTransferred(address,address)"), [padded(HOLDER), padded(ADDR)])
    w, got = make(tmp_path, [{"topic0": LIMITS, "name": "L"}], [lg])
    assert w._scan(1, 10) == 1
    assert got[0].event == "OwnershipTransferred" and got[0].source == "Ownable"


def test_failed_backfill_says_so_without_a_traceback_or_the_key(tmp_path, capsys, monkeypatch):
    from ownerwatch import cli
    f = tmp_path / "c.yaml"
    f.write_text(f'rpc_url: "https://rpc.example/secretkey"\nstate_file: "{tmp_path}/s.json"\ncontracts: [{{address: "{ADDR}"}}]\n')

    def boom(self, a, b):
        raise RuntimeError("403 Forbidden for url: https://rpc.example/secretkey")
    monkeypatch.setattr(Watcher, "scan_range", boom)
    monkeypatch.setattr("sys.argv", ["ownerwatch", "backfill", "--config", str(f), "--from-block", "1", "--to-block", "2"])
    assert cli.main() == 2
    err = capsys.readouterr().err
    assert "could not read blocks 1-2" in err and "secretkey" not in err

