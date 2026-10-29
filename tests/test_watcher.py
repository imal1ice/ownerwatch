"""End-to-end test against a local anvil node. Requires foundry (anvil, forge)."""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from web3 import Web3

from ownerwatch.alerts import Dispatcher
from ownerwatch.config import Alerts, Collection, Config, Contract, Token, Treasury
from ownerwatch.watcher import Watcher

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.skipif(shutil.which("anvil") is None or shutil.which("forge") is None,
                                reason="foundry not installed")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def anvil():
    port = _free_port()
    proc = subprocess.Popen(["anvil", "--port", str(port), "--silent"])
    url = f"http://127.0.0.1:{port}"
    w3 = Web3(Web3.HTTPProvider(url))
    for _ in range(100):
        try:
            if w3.is_connected():
                break
        except Exception:
            pass
        time.sleep(0.1)
    yield w3
    proc.terminate()
    proc.wait()


@pytest.fixture(scope="module")
def artifacts():
    subprocess.run(["forge", "build", "--root", str(FIXTURES)], check=True, capture_output=True)
    out = {}
    for name in ("Admin", "Token", "NFT", "Multi", "Timelock", "LegacyTimelock", "Gov", "RoleBox", "Proto", "SafeLike", "Payloads", "SoladyTimelockLike", "OwnedTimelockLike", "ProxyFactoryLike",
                 "AaveProviderLike", "ExecutorLike", "PayloadsControllerLike", "RoleLog"):
        art = json.loads((FIXTURES / "out" / "Admin.sol" / f"{name}.json").read_text())
        out[name] = (art["abi"], art["bytecode"]["object"])
    return out


def _deploy(w3, abi, bytecode):
    acct = w3.eth.accounts[0]
    tx = w3.eth.contract(abi=abi, bytecode=bytecode).constructor().transact({"from": acct})
    rcpt = w3.eth.wait_for_transaction_receipt(tx)
    return w3.eth.contract(address=rcpt["contractAddress"], abi=abi)


def test_admin_events_and_treasury_outflow(anvil, artifacts, tmp_path):
    w3 = anvil
    deployer = w3.eth.accounts[0]
    admin = _deploy(w3, *artifacts["Admin"])
    token = _deploy(w3, *artifacts["Token"])
    deploy_block = w3.eth.block_number

    cfg = Config(
        rpc_url="unused", chain_name="anvil", confirmations=0, start_block=deploy_block + 1,
        state_file=str(tmp_path / "cursor.json"),
        contracts=[Contract(admin.address, "TestAdmin")],
        treasuries=[Treasury(deployer, "Treasury", [Token(token.address, "TST", 18, 1000)])],
        alerts=Alerts(),
    )
    got: list = []
    watcher = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)

    new_owner = w3.eth.accounts[1]
    admin.functions.transferOwnership(new_owner).transact({"from": deployer})
    admin.functions.grantRole(b"\x11" * 32, new_owner).transact({"from": deployer})
    admin.functions.pause().transact({"from": deployer})
    admin.functions.upgradeTo(new_owner).transact({"from": deployer})
    token.functions.transfer(new_owner, 999 * 10**18).transact({"from": deployer})     # below threshold
    token.functions.transfer(new_owner, 5000 * 10**18).transact({"from": deployer})    # above threshold
    last = token.functions.transfer(deployer, 5000 * 10**18).transact({"from": new_owner})  # not from treasury
    w3.eth.wait_for_transaction_receipt(last)

    n = watcher.poll_once()
    assert n == 5
    by_event = {a.event: a for a in got}
    assert set(by_event) == {"OwnershipTransferred", "RoleGranted", "Paused", "Upgraded", "Transfer"}
    assert by_event["OwnershipTransferred"].severity == "critical"
    assert new_owner in by_event["OwnershipTransferred"].message
    assert by_event["OwnershipTransferred"].label == "TestAdmin"
    assert by_event["Transfer"].message.startswith("5,000.00 TST")
    assert by_event["Transfer"].label == "Treasury"

    # cursor advanced; second poll finds nothing new
    assert watcher.poll_once() == 0
    assert json.loads((tmp_path / "cursor.json").read_text())["last_block"] == w3.eth.block_number

    # fresh watcher resumes from cursor and sees a new event only once
    w3.eth.wait_for_transaction_receipt(admin.functions.pause().transact({"from": deployer}))
    got2: list = []
    w2 = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got2.append]), w3=w3)
    assert w2.poll_once() == 1
    assert got2[0].event == "Paused"


def test_nft_native_and_timelock(anvil, artifacts, tmp_path, monkeypatch):
    import ownerwatch.watcher as wmod
    monkeypatch.setattr(wmod, "describe_call", lambda d, *a: "transferOwnership(address) [0xf2fde38b]")
    w3 = anvil
    deployer, other = w3.eth.accounts[0], w3.eth.accounts[1]
    nft = _deploy(w3, *artifacts["NFT"])
    multi = _deploy(w3, *artifacts["Multi"])
    timelock = _deploy(w3, *artifacts["Timelock"])
    start = w3.eth.block_number + 1
    cfg = Config(
        rpc_url="unused", chain_name="anvil", confirmations=0, start_block=start,
        state_file=str(tmp_path / "cursor.json"),
        contracts=[Contract(timelock.address, "TL")],
        treasuries=[Treasury(deployer, "Treasury", [], [Collection(nft.address, "Apes"), Collection(multi.address, "Multi")],
                             min_native_drop=1.0)],
        alerts=Alerts(),
    )
    got: list = []
    watcher = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    assert watcher.poll_once() == 0          # records baseline balance, nothing to report yet

    nft.functions.transferFrom(deployer, other, 7).transact({"from": deployer})
    nft.functions.transferFrom(other, deployer, 8).transact({"from": deployer})          # inbound: ignored
    multi.functions.single(deployer, other, 1, 3).transact({"from": deployer})
    multi.functions.batch(deployer, other, [1, 2], [1, 1]).transact({"from": deployer})
    timelock.functions.schedule(other, bytes.fromhex("f2fde38b") + b"\x00" * 32).transact({"from": deployer})
    w3.eth.wait_for_transaction_receipt(w3.eth.send_transaction({"from": deployer, "to": other, "value": 2 * 10**18}))

    assert watcher.poll_once() == 5
    events = sorted((a.event, a.source) for a in got)
    assert events == sorted([("Transfer", "ERC-721"), ("TransferSingle", "ERC-1155"), ("TransferBatch", "ERC-1155"),
                             ("CallScheduled", "TimelockController"), ("BalanceDrop", "native")])
    by = {a.event: a for a in got}
    assert "NFT #7 of Apes" in by["Transfer"].message
    assert "batch of 2 token ids of Multi" in by["TransferBatch"].message
    assert "calling transferOwnership(address) [0xf2fde38b]" in by["CallScheduled"].message
    assert "native balance fell 2.0" in by["BalanceDrop"].message
    assert watcher.poll_once() == 0


def test_legacy_timelock(anvil, artifacts, tmp_path):
    w3 = anvil
    deployer = w3.eth.accounts[0]
    tl = _deploy(w3, *artifacts["LegacyTimelock"])
    cfg = Config(rpc_url="unused", chain_name="anvil", confirmations=0, start_block=w3.eth.block_number + 1,
                 state_file=str(tmp_path / "c.json"), contracts=[Contract(tl.address, "Uni TL")], alerts=Alerts())
    got: list = []
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    tl.functions.setDelay(86400).transact({"from": deployer})
    w3.eth.wait_for_transaction_receipt(tl.functions.queue(deployer, "setFeeProtocol(uint8,uint8)").transact({"from": deployer}))
    assert w.poll_once() == 2
    by = {a.event: a for a in got}
    assert by["NewDelay"].severity == "critical" and "86400s" in by["NewDelay"].message
    assert "sig 'setFeeProtocol(uint8,uint8)'" in by["QueueTransaction"].message


def test_governor_and_aragon(anvil, artifacts, tmp_path, monkeypatch):
    import ownerwatch.watcher as wmod
    monkeypatch.setattr(wmod, "describe_call", lambda d, *a: "setFee(uint256) [0x69fe0e2d]")
    w3 = anvil
    deployer = w3.eth.accounts[0]
    gov = _deploy(w3, *artifacts["Gov"])
    cfg = Config(rpc_url="unused", chain_name="anvil", confirmations=0, start_block=w3.eth.block_number + 1,
                 state_file=str(tmp_path / "c.json"), contracts=[Contract(gov.address, "Gov")], alerts=Alerts())
    got: list = []
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    gov.functions.propose("\n   \n").transact({"from": deployer})   # whitespace-only description must not stall
    gov.functions.propose("# Raise fee switch\nlong body").transact({"from": deployer})
    gov.functions.setDelay(7200).transact({"from": deployer})
    w3.eth.wait_for_transaction_receipt(gov.functions.setApp(deployer).transact({"from": deployer}))
    assert w.poll_once() == 4
    titles = [a.message for a in got if a.event == "ProposalCreated"]
    assert any("(no description)" in t for t in titles) and any("2 targets: # Raise fee switch" in t for t in titles)
    assert all("actions: 0x" in t and "setFee(uint256)" in t for t in titles)
    by = {a.event: a for a in got}
    assert by["VotingDelaySet"].severity == "critical" and "1 -> 7200" in by["VotingDelaySet"].message
    assert by["SetApp"].source == "AragonOS" and deployer in by["SetApp"].message


def test_protocol_events(anvil, artifacts, tmp_path):
    w3 = anvil
    deployer = w3.eth.accounts[0]
    proto = _deploy(w3, *artifacts["Proto"])
    cfg = Config(rpc_url="unused", chain_name="anvil", confirmations=0, start_block=w3.eth.block_number + 1,
                 state_file=str(tmp_path / "c.json"), contracts=[Contract(proto.address, "P")], alerts=Alerts())
    got: list = []
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    w3.eth.wait_for_transaction_receipt(proto.functions.poke(w3.eth.accounts[1]).transact({"from": deployer}))
    assert w.poll_once() == 4
    by = {a.event: a for a in got}
    assert by["PoolUpdated"].source == "AaveV3" and by["PoolUpdated"].severity == "critical"
    assert by["SetCurator"].source == "MetaMorpho"
    assert "cap set for market 0x" in by["SetCap"].message and ": 5 by" in by["SetCap"].message
    assert by["Stopped"].source == "Lido"


def test_safe_execution_events(anvil, artifacts, tmp_path):
    w3 = anvil
    deployer = w3.eth.accounts[0]
    sl = _deploy(w3, *artifacts["SafeLike"])
    cfg = Config(rpc_url="unused", chain_name="anvil", confirmations=0, start_block=w3.eth.block_number + 1,
                 state_file=str(tmp_path / "c.json"), contracts=[Contract(sl.address, "Safe")], alerts=Alerts())
    got: list = []
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    sl.functions.viaModule().transact({"from": deployer})
    w3.eth.wait_for_transaction_receipt(sl.functions.exec().transact({"from": deployer}))
    assert w.poll_once() == 2
    by = {a.event: a for a in got}
    assert by["ExecutionFromModuleSuccess"].severity == "high" and deployer in by["ExecutionFromModuleSuccess"].message
    assert by["ExecutionSuccess"].severity == "info"


def test_aave_payloads_controller(anvil, artifacts, tmp_path, monkeypatch):
    import ownerwatch.watcher as wmod
    monkeypatch.setattr(wmod, "describe_call", lambda d, *a: "execute() [0x61461954]")
    w3 = anvil
    deployer = w3.eth.accounts[0]
    pc = _deploy(w3, *artifacts["Payloads"])
    cfg = Config(rpc_url="unused", chain_name="anvil", confirmations=0, start_block=w3.eth.block_number + 1,
                 state_file=str(tmp_path / "c.json"), contracts=[Contract(pc.address, "PC")], alerts=Alerts())
    got: list = []
    w = Watcher(cfg, Dispatcher(cfg.alerts, sinks=[got.append]), w3=w3)
    w3.eth.wait_for_transaction_receipt(pc.functions.poke(w3.eth.accounts[1]).transact({"from": deployer}))
    assert w.poll_once() == 4
    by = {a.event: a for a in got}
    created = by["PayloadCreated"]
    assert created.source == "AavePayloads" and created.severity == "medium"
    assert "payload 42 created by " + deployer in created.message and "2 actions" in created.message
    assert "delegatecall " + w3.eth.accounts[1] + ": execute()" in created.message and "setFee(7)" in created.message
    assert by["PayloadQueued"].severity == "high" and by["GuardianUpdated"].severity == "critical"
