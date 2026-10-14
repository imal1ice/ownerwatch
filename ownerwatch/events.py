"""Catalog of admin-surface events worth waking someone up for.

Each entry maps an event signature to an ABI fragment, a severity and a
human description. Severity levels: info < medium < high < critical.
"""
from __future__ import annotations

from dataclasses import dataclass

from web3 import Web3

SEVERITIES = ["info", "medium", "high", "critical"]


@dataclass(frozen=True)
class EventSpec:
    name: str
    signature: str
    abi: dict
    severity: str
    describe: str  # format string using decoded args
    source: str    # which standard this comes from


def _inp(name: str, typ: str, indexed: bool) -> dict:
    return {"name": name, "type": typ, "indexed": indexed}


def _abi(name: str, *inputs: dict) -> dict:
    return {"anonymous": False, "type": "event", "name": name, "inputs": list(inputs)}


CATALOG: list[EventSpec] = [
    # Ownable / Ownable2Step
    EventSpec(
        "OwnershipTransferred", "OwnershipTransferred(address,address)",
        _abi("OwnershipTransferred", _inp("previousOwner", "address", True), _inp("newOwner", "address", True)),
        "critical", "owner changed {previousOwner} -> {newOwner}", "Ownable"),
    EventSpec(
        "OwnershipTransferStarted", "OwnershipTransferStarted(address,address)",
        _abi("OwnershipTransferStarted", _inp("previousOwner", "address", True), _inp("newOwner", "address", True)),
        "high", "ownership transfer started {previousOwner} -> {newOwner} (pending accept)", "Ownable2Step"),
    # AccessControl
    EventSpec(
        "RoleGranted", "RoleGranted(bytes32,address,address)",
        _abi("RoleGranted", _inp("role", "bytes32", True), _inp("account", "address", True), _inp("sender", "address", True)),
        "high", "role {role} granted to {account} by {sender}", "AccessControl"),
    EventSpec(
        "RoleRevoked", "RoleRevoked(bytes32,address,address)",
        _abi("RoleRevoked", _inp("role", "bytes32", True), _inp("account", "address", True), _inp("sender", "address", True)),
        "high", "role {role} revoked from {account} by {sender}", "AccessControl"),
    EventSpec(
        "RoleAdminChanged", "RoleAdminChanged(bytes32,bytes32,bytes32)",
        _abi("RoleAdminChanged", _inp("role", "bytes32", True), _inp("previousAdminRole", "bytes32", True), _inp("newAdminRole", "bytes32", True)),
        "critical", "admin of role {role} changed {previousAdminRole} -> {newAdminRole}", "AccessControl"),
    # ERC-1967 proxies
    EventSpec(
        "Upgraded", "Upgraded(address)",
        _abi("Upgraded", _inp("implementation", "address", True)),
        "critical", "proxy implementation upgraded to {implementation}", "ERC-1967"),
    EventSpec(
        "AdminChanged", "AdminChanged(address,address)",
        _abi("AdminChanged", _inp("previousAdmin", "address", False), _inp("newAdmin", "address", False)),
        "critical", "proxy admin changed {previousAdmin} -> {newAdmin}", "ERC-1967"),
    EventSpec(
        "BeaconUpgraded", "BeaconUpgraded(address)",
        _abi("BeaconUpgraded", _inp("beacon", "address", True)),
        "critical", "proxy beacon changed to {beacon}", "ERC-1967"),
    # Pausable
    EventSpec(
        "Paused", "Paused(address)",
        _abi("Paused", _inp("account", "address", False)),
        "medium", "contract paused by {account}", "Pausable"),
    EventSpec(
        "Unpaused", "Unpaused(address)",
        _abi("Unpaused", _inp("account", "address", False)),
        "medium", "contract unpaused by {account}", "Pausable"),
    # TimelockController
    EventSpec(
        "CallScheduled", "CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)",
        _abi("CallScheduled", _inp("id", "bytes32", True), _inp("index", "uint256", True), _inp("target", "address", False),
             _inp("value", "uint256", False), _inp("data", "bytes", False), _inp("predecessor", "bytes32", False), _inp("delay", "uint256", False)),
        "high", "timelock call scheduled: target {target} value {value} delay {delay}s id {id}", "TimelockController"),
    EventSpec(
        "CallExecuted", "CallExecuted(bytes32,uint256,address,uint256,bytes)",
        _abi("CallExecuted", _inp("id", "bytes32", True), _inp("index", "uint256", True), _inp("target", "address", False),
             _inp("value", "uint256", False), _inp("data", "bytes", False)),
        "high", "timelock call executed: target {target} value {value} id {id}", "TimelockController"),
    EventSpec(
        "Cancelled", "Cancelled(bytes32)",
        _abi("Cancelled", _inp("id", "bytes32", True)),
        "medium", "timelock call cancelled id {id}", "TimelockController"),
    EventSpec(
        "MinDelayChange", "MinDelayChange(uint256,uint256)",
        _abi("MinDelayChange", _inp("oldDuration", "uint256", False), _inp("newDuration", "uint256", False)),
        "critical", "timelock min delay changed {oldDuration}s -> {newDuration}s", "TimelockController"),
    # Safe (Gnosis Safe)
    EventSpec(
        "AddedOwner", "AddedOwner(address)",
        _abi("AddedOwner", _inp("owner", "address", False)),
        "critical", "Safe owner added {owner}", "Safe"),
    EventSpec(
        "RemovedOwner", "RemovedOwner(address)",
        _abi("RemovedOwner", _inp("owner", "address", False)),
        "critical", "Safe owner removed {owner}", "Safe"),
    EventSpec(
        "ChangedThreshold", "ChangedThreshold(uint256)",
        _abi("ChangedThreshold", _inp("threshold", "uint256", False)),
        "critical", "Safe threshold changed to {threshold}", "Safe"),
    EventSpec(
        "EnabledModule", "EnabledModule(address)",
        _abi("EnabledModule", _inp("module", "address", False)),
        "critical", "Safe module enabled {module}", "Safe"),
    EventSpec(
        "DisabledModule", "DisabledModule(address)",
        _abi("DisabledModule", _inp("module", "address", False)),
        "high", "Safe module disabled {module}", "Safe"),
    EventSpec(
        "ChangedGuard", "ChangedGuard(address)",
        _abi("ChangedGuard", _inp("guard", "address", False)),
        "critical", "Safe guard changed to {guard}", "Safe"),
    EventSpec(
        "ChangedFallbackHandler", "ChangedFallbackHandler(address)",
        _abi("ChangedFallbackHandler", _inp("handler", "address", False)),
        "high", "Safe fallback handler changed to {handler}", "Safe"),
]

TRANSFER_SPEC = EventSpec(
    "Transfer", "Transfer(address,address,uint256)",
    _abi("Transfer", _inp("from", "address", True), _inp("to", "address", True), _inp("value", "uint256", False)),
    "high", "{amount} {symbol} sent from {from} to {to}", "ERC-20")


def topic0(signature: str) -> str:
    return Web3.keccak(text=signature).hex()


def _norm(t: str) -> str:
    return t if t.startswith("0x") else "0x" + t


BY_TOPIC: dict[str, EventSpec] = {_norm(topic0(s.signature)): s for s in CATALOG}
TRANSFER_TOPIC = _norm(topic0(TRANSFER_SPEC.signature))
ADMIN_TOPICS: list[str] = list(BY_TOPIC.keys())


def severity_rank(level: str) -> int:
    return SEVERITIES.index(level)
