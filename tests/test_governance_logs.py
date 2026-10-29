"""Decoding of governance events recorded on Ethereum mainnet (tests/fixtures/governance_logs.json).

Every log here is real: one or more per event type ownerwatch learned for Sky's pause and chief, Lido's
Dual Governance and Emergency Protected Timelock, Rocket Pool's DAOs, CoW's solver allow-list, Gearbox's ACL
and the 0x Settler deployer. No node is needed: the decoders only read the log itself."""
import json
from pathlib import Path

import pytest
from hexbytes import HexBytes
from web3 import Web3

from ownerwatch.alerts import Dispatcher
from ownerwatch.config import Alerts, Config, Contract
from ownerwatch.events import ADMIN_TOPICS
from ownerwatch.watcher import Watcher

LOGS = json.loads((Path(__file__).parent / "fixtures" / "governance_logs.json").read_text())


def _log(raw: dict) -> dict:
    return {"address": raw["address"], "topics": [HexBytes(t) for t in raw["topics"]], "data": HexBytes(raw["data"]),
            "blockNumber": raw["blockNumber"], "transactionHash": HexBytes(raw["transactionHash"]), "logIndex": raw["logIndex"],
            # not recorded, and not read by any decoder; web3's process_log still requires them
            "transactionIndex": 0, "blockHash": HexBytes("0x" + "00" * 32)}


@pytest.fixture(scope="module")
def watcher(tmp_path_factory):
    contracts = [Contract(Web3.to_checksum_address(a), "x") for a in {r["address"] for r in LOGS}]
    cfg = Config(rpc_url="unused", contracts=contracts, state_file=str(tmp_path_factory.mktemp("s") / "c.json"),
                 explorer_url="https://etherscan.io")
    return Watcher(cfg, Dispatcher(Alerts()), w3=Web3())


def decoded(watcher, topic_prefix: str):
    raws = [r for r in LOGS if r["topics"][0].startswith(topic_prefix) and r["topics"][0] in ADMIN_TOPICS]
    assert raws, f"no fixture for {topic_prefix}"
    out = []
    for raw in raws:
        lg = _log(raw)
        out.append(watcher._decode_admin(lg))
    assert all(out), f"{topic_prefix} did not decode"
    return out


def test_every_recorded_log_decodes(watcher):
    # the 0x deployer's ERC-721 Transfers are recorded to pin down that they are not watched
    for raw in LOGS:
        if raw["topics"][0].startswith("0xddf252ad"):
            assert raw["topics"][0] not in ADMIN_TOPICS
        else:
            decoded(watcher, raw["topics"][0][:10])


@pytest.mark.parametrize("prefix,event,source,text", [
    ("0x46d2fbbb", "SpellPlotted", "DSPause", "plotted, executable from 2026-"),
    ("0x168ccd67", "SpellExecuted", "DSPause", "executed"),
    ("0x2b07094b", "Lift", "DSChief", "new hat lifted in the chief"),
    ("0x24ae498e", "ProposalSubmitted", "EmergencyProtectedTimelock", "calls"),
    ("0x8b9c2cfe", "ProposalScheduled", "EmergencyProtectedTimelock", "scheduled for execution"),
    ("0x712ae138", "ProposalExecuted", "EmergencyProtectedTimelock", "timelock proposal"),
    ("0x232ce03d", "ProposalSubmitted", "DualGovernance", "Dual Governance proposal"),
    ("0x401dce14", "DualGovernanceStateChanged", "DualGovernance", "Dual Governance state "),
    ("0x3b7c90df", "ProposalExecuted", "RocketDAO", "Rocket Pool DAO proposal"),
    ("0x253b2d54", "ContractUpgraded", "RocketDAO", "upgraded"),
    ("0xf0444472", "UpgradePending", "RocketDAO", "pending"),
    ("0x41f9d09d", "SolverAdded", "GPv2AllowList", "solver added"),
    ("0x640e18a2", "SolverRemoved", "GPv2AllowList", "solver removed"),
    ("0xd400da6c", "UnpausableAdminAdded", "GearboxACL", "unpausable admin added"),
    ("0x1998397e", "UnpausableAdminRemoved", "GearboxACL", "unpausable admin removed"),
    ("0xaa94c583", "Deployed", "SettlerDeployer", "new code deployed for feature"),
])
def test_event_names_and_messages(watcher, prefix, event, source, text):
    for alert in decoded(watcher, prefix):
        assert (alert.event, alert.source) == (event, source)
        assert text in alert.message
        assert alert.tx_hash.startswith("https://etherscan.io/tx/0x")


def test_spell_plot_reads_the_spell_and_eta_from_calldata(watcher):
    [alert] = decoded(watcher, "0x46d2fbbb")
    usr = alert.message.split()[1]
    assert Web3.is_checksum_address(usr)
    assert alert.severity == "high"


def test_dual_governance_states_are_named(watcher):
    for alert in decoded(watcher, "0x401dce14"):
        states = alert.message.removeprefix("Dual Governance state ").split(" -> ")
        assert all(s in {"NotInitialized", "Normal", "VetoSignalling", "VetoSignallingDeactivation", "VetoCooldown", "RageQuit"}
                   for s in states)
