"""ERC-8241 disclosures checked against chain state: an accurate one, a stale one, and one with an omission."""
import copy
import json
import shutil

import pytest

from ownerwatch.cli import main
from ownerwatch.disclosure import Checker, draft, manifest_hash
from tests.test_watcher import _deploy, anvil, artifacts  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="foundry not installed")


@pytest.fixture
def deployed(anvil, artifacts):  # noqa: F811
    """A contract owned by the deployer (OWNERSHIP) and an AccessControl contract (ROLE DEFAULT_ADMIN)."""
    owned = _deploy(anvil, *artifacts["Admin"])
    roles = _deploy(anvil, *artifacts["RoleBox"])
    return anvil, [owned.address, roles.address]


def test_drafted_disclosure_checks_clean(deployed):
    w3, addrs = deployed
    d = draft(w3, addrs, "Test")
    assert d["standard"] == "ERC-8241" and d["protocol"]["manifestHash"] == manifest_hash(d)
    assert {p["kind"] for p in d["powers"]} == {"OWNERSHIP", "ROLE"}
    report = Checker(w3).check(d)
    assert report["summary"]["mismatch"] == 0 and report["undisclosed"] == []
    assert report["summary"]["ok"] >= 5          # manifest hash, nodes, components, powers
    assert report["blockHash"].startswith("0x") and report["block"] == w3.eth.block_number


def test_stale_disclosure_is_a_mismatch(deployed):
    w3, addrs = deployed
    d = draft(w3, addrs, "Test")
    stale = copy.deepcopy(d)
    owner_power = next(p for p in stale["powers"] if p["kind"] == "OWNERSHIP")
    node = next(n for n in stale["nodes"] if n["nodeId"] == owner_power["controllerNodeId"])
    node["address"] = w3.eth.accounts[1]          # the docs still name the old owner
    report = Checker(w3).check(stale)
    statuses = {(r["record"], r["id"]): r["status"] for r in report["results"]}
    assert statuses[("power", owner_power["powerId"])] == "mismatch"
    assert statuses[("protocol", "manifestHash")] == "mismatch"     # the file changed after it was hashed
    assert any(u["kind"] == "OWNERSHIP" for u in report["undisclosed"])   # the real owner is now undeclared


def test_omitted_power_is_undisclosed(deployed):
    w3, addrs = deployed
    d = draft(w3, addrs, "Test")
    d["powers"] = [p for p in d["powers"] if p["kind"] != "ROLE"]
    d["protocol"]["manifestHash"] = manifest_hash(d)
    report = Checker(w3).check(d)
    assert report["summary"]["mismatch"] == 0
    assert [(u["kind"], u["role"]) for u in report["undisclosed"]] == [("ROLE", "DEFAULT_ADMIN_ROLE")]


def test_unverifiable_kinds_are_never_ok(deployed):
    w3, addrs = deployed
    d = draft(w3, addrs, "Test")
    d["powers"].append({"powerId": "oracle", "kind": "ORACLE_UPDATE", "enabled": True,
                        "target": d["components"][0]["componentId"], "controllerNodeId": d["nodes"][0]["nodeId"]})
    report = Checker(w3).check(d)
    assert [r["status"] for r in report["results"] if r["id"] == "oracle"] == ["unverifiable"]


def test_cli_exit_code(deployed, tmp_path, capsys):
    w3, addrs = deployed
    rpc = w3.provider.endpoint_uri
    assert main(["disclosure", "draft", *addrs, "--rpc", rpc, "--name", "T"]) == 0
    d = json.loads(capsys.readouterr().out)
    f = tmp_path / "d.json"
    f.write_text(json.dumps(d))
    assert main(["disclosure", "check", str(f), "--rpc", rpc]) == 0
    d["powers"] = d["powers"][1:]
    f.write_text(json.dumps(d))
    assert main(["disclosure", "check", str(f), "--rpc", rpc]) == 1
    assert "UNDISCLOSED" in capsys.readouterr().out


def test_drafted_edges_follow_the_owner_and_catch_a_stale_one(deployed):
    w3, addrs = deployed
    d = draft(w3, addrs, "Test")
    owner_edges = [e for e in d["edges"] if e["kind"] == "OWNER_OF"]
    assert owner_edges, "the owner of a component appears as an OWNER_OF edge"
    nodes = {n["nodeId"]: n for n in d["nodes"]}
    nodes[owner_edges[0]["from"]]["address"] = w3.eth.accounts[2]
    report = Checker(w3).check(d)
    assert {r["status"] for r in report["results"] if r["id"] == owner_edges[0]["edgeId"]} == {"mismatch"}


def test_node_parameters_are_checked(anvil, artifacts):  # noqa: F811
    w3 = anvil
    tl = _deploy(w3, *artifacts["OwnedTimelockLike"])          # delay() = 172800, owner() = deployer
    d = draft(w3, [tl.address], "T")
    node = next(n for n in d["nodes"] if n["type"] == "TIMELOCK")
    assert node["delay"] == 172800
    node["delay"] = 86400
    report = Checker(w3).check(d)
    [r] = [r for r in report["results"] if r["record"] == "node" and r["id"] == node["nodeId"]]
    assert r["status"] == "mismatch" and "delay declared 86400, on-chain 172800" in r["detail"]
