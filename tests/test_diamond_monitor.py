"""The default event catalog alerts on an EIP-2535 Diamond's facet changes: a diamondCut replaces facet
code, an upgrade no ERC-1967 slot reveals, so without a DiamondCut entry a monitored diamond's upgrades
pass unseen."""
from eth_abi import encode

from ownerwatch.alerts import Dispatcher
from ownerwatch.config import Config, Contract
from ownerwatch.events import BY_TOPIC, _norm, topic0
from ownerwatch.watcher import Watcher
from tests.test_custom_events import ADDR, W3, log

DIAMONDCUT = "DiamondCut((address,uint8,bytes4[])[],address,bytes)"


def _data(facets, init="0x" + "00" * 20, calldata=b""):
    return encode(["(address,uint8,bytes4[])[]", "address", "bytes"], [facets, init, calldata])


def test_diamondcut_is_in_the_default_catalog():
    spec = BY_TOPIC[_norm(topic0(DIAMONDCUT))]
    assert spec.name == "DiamondCut" and spec.severity == "critical" and spec.source == "EIP-2535"


def test_diamondcut_log_alerts_critical(tmp_path):
    facets = [("0x" + "11" * 20, 0, [b"\xaa\xbb\xcc\xdd"]),
              ("0x" + "22" * 20, 2, [b"\x12\x34\x56\x78", b"\xde\xad\xbe\xef"])]
    lg = log(topic0(DIAMONDCUT), data=_data(facets))
    got = []
    cfg = Config(rpc_url="http://x", start_block=1, confirmations=0, state_file=str(tmp_path / "s.json"),
                 contracts=[Contract(ADDR, "Diamond")])
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=W3([lg]))
    assert w._scan(1, 10) == 1
    a = got[0]
    assert (a.event, a.severity, a.source, a.label) == ("DiamondCut", "critical", "EIP-2535", "Diamond")
    assert "2 facet change(s)" in a.message
