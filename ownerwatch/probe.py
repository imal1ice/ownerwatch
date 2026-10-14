"""Inspect an address's admin surface: proxy slots, owner/admin, Safe
owners and threshold, timelock delay. Classifies each controlling address
and suggests an ownerwatch config. Read-only; works on any EVM chain."""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml
from web3 import Web3

IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16)
BEACON_SLOT = int("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16)
ZERO = "0x" + "00" * 20


def _sel(sig: str) -> bytes:
    return Web3.keccak(text=sig)[:4]


ROLES = {
    "DEFAULT_ADMIN_ROLE": b"\x00" * 32,
    "PROPOSER_ROLE": Web3.keccak(text="PROPOSER_ROLE"),
    "EXECUTOR_ROLE": Web3.keccak(text="EXECUTOR_ROLE"),
    "CANCELLER_ROLE": Web3.keccak(text="CANCELLER_ROLE"),
    "UPGRADER_ROLE": Web3.keccak(text="UPGRADER_ROLE"),
    "PAUSER_ROLE": Web3.keccak(text="PAUSER_ROLE"),
    "MINTER_ROLE": Web3.keccak(text="MINTER_ROLE"),
}


@dataclass
class Node:
    address: str
    kind: str = "unknown"          # eoa | safe | timelock | legacy-timelock | proxy | contract
    code_size: int = 0
    implementation: str | None = None
    proxy_admin: str | None = None
    beacon: str | None = None
    owner: str | None = None
    pending_owner: str | None = None
    admin: str | None = None
    safe_threshold: int | None = None
    safe_owners: list[str] = field(default_factory=list)
    delay: int | None = None
    paused: bool | None = None
    roles: dict[str, list[str]] = field(default_factory=dict)   # role name -> holders found among probed addresses
    open_executor: bool | None = None
    notes: list[str] = field(default_factory=list)


class Prober:
    def __init__(self, w3: Web3):
        self.w3 = w3
        self.seen: dict[str, Node] = {}

    # ---- low level ----
    def _call(self, addr: str, sig: str) -> bytes | None:
        try:
            r = self.w3.eth.call({"to": addr, "data": _sel(sig)})
            return bytes(r) if r else None
        except Exception as e:  # noqa: BLE001
            # a revert means "this contract doesn't have that function"; a transport
            # error means the RPC is unusable for probing and must not be hidden
            if type(e).__name__ in ("HTTPError", "ConnectionError", "Timeout", "ReadTimeout"):
                raise RuntimeError(f"RPC refused eth_call ({e}); use an RPC that supports reads, e.g. https://eth.drpc.org") from e
            return None

    def _addr(self, addr: str, sig: str) -> str | None:
        r = self._call(addr, sig)
        if r and len(r) >= 32:
            a = Web3.to_checksum_address("0x" + r[12:32].hex())
            return None if a == ZERO else a
        return None

    def _uint(self, addr: str, sig: str) -> int | None:
        r = self._call(addr, sig)
        return int.from_bytes(r[:32], "big") if r and len(r) >= 32 else None

    def _has_role(self, addr: str, role: bytes, who: str) -> bool | None:
        data = _sel("hasRole(bytes32,address)") + role + bytes(12) + bytes.fromhex(who[2:])
        try:
            r = self.w3.eth.call({"to": addr, "data": data})
        except Exception:  # noqa: BLE001
            return None
        return bool(int.from_bytes(bytes(r)[:32], "big")) if r and len(r) == 32 else None

    def _supports_access_control(self, addr: str) -> bool:
        return self._has_role(addr, ROLES["DEFAULT_ADMIN_ROLE"], ZERO) is not None

    def check_roles(self, candidates: list[str]) -> None:
        """Second pass: for every AccessControl contract seen, test which of the
        probed addresses hold key roles. Also detects an open executor on timelocks."""
        for n in list(self.seen.values()):
            if n.kind == "eoa" or not self._supports_access_control(n.address):
                continue
            for name, role in ROLES.items():
                holders = [c for c in candidates if c != n.address and self._has_role(n.address, role, c)]
                if holders:
                    n.roles[name] = holders
            if n.kind == "timelock":
                n.open_executor = self._has_role(n.address, ROLES["EXECUTOR_ROLE"], ZERO)
                if n.open_executor:
                    n.notes.append("executor role is open: anyone can execute a matured operation")
            for who in n.roles.get("DEFAULT_ADMIN_ROLE", []):
                c = self.seen.get(who)
                if c and c.kind == "eoa":
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by EOA {who}")
                elif c and c.kind == "safe" and c.safe_threshold == 1:
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by 1-of-N Safe {who}")

    def _slot_addr(self, addr: str, slot: int) -> str | None:
        v = self.w3.eth.get_storage_at(addr, slot)
        a = Web3.to_checksum_address("0x" + bytes(v)[-20:].hex())
        return None if a == ZERO else a

    # ---- probe ----
    def probe(self, address: str, depth: int = 0) -> Node:
        address = Web3.to_checksum_address(address)
        if address in self.seen:
            return self.seen[address]
        n = Node(address=address)
        self.seen[address] = n
        n.code_size = len(self.w3.eth.get_code(address))
        if n.code_size == 0:
            n.kind = "eoa"
            return n
        n.implementation = self._slot_addr(address, IMPL_SLOT)
        n.proxy_admin = self._slot_addr(address, ADMIN_SLOT)
        n.beacon = self._slot_addr(address, BEACON_SLOT)
        thr = self._uint(address, "getThreshold()")
        owners = self._call(address, "getOwners()")
        if thr is not None and owners and len(owners) >= 64:
            n.kind = "safe"
            n.safe_threshold = thr
            count = int.from_bytes(owners[32:64], "big")
            n.safe_owners = [Web3.to_checksum_address("0x" + owners[64 + 32 * i + 12: 64 + 32 * i + 32].hex())
                             for i in range(count)]
            if thr == 1:
                n.notes.append("1-of-N Safe: a single key can act")
            elif thr <= count // 2:
                n.notes.append(f"{thr}-of-{count} Safe: fewer than half the owners are needed")
        d = self._uint(address, "getMinDelay()")
        if d is not None and n.kind == "unknown":
            n.kind = "timelock"
            n.delay = d
        legacy = self._uint(address, "delay()")
        legacy_admin = self._addr(address, "admin()")
        if legacy is not None and legacy_admin and n.kind == "unknown":
            n.kind = "legacy-timelock"
            n.delay = legacy
            n.admin = legacy_admin
        if n.kind == "unknown":
            n.kind = "proxy" if (n.implementation or n.beacon) else "contract"
        n.owner = self._addr(address, "owner()")
        n.pending_owner = self._addr(address, "pendingOwner()")
        if n.admin is None:
            n.admin = n.proxy_admin or self._addr(address, "admin()") if n.kind != "safe" else None
        p = self._call(address, "paused()")
        if p is not None and len(p) == 32:
            n.paused = bool(int.from_bytes(p, "big"))
        if n.kind in ("timelock", "legacy-timelock") and n.delay is not None:
            if n.delay == 0:
                n.notes.append("timelock delay is 0")
            elif n.delay < 86400:
                n.notes.append(f"timelock delay is only {n.delay // 3600}h")
        # follow controllers one level down
        if depth < 2:
            for ctl in {n.owner, n.admin, n.proxy_admin}:
                if ctl and ctl != address:
                    c = self.probe(ctl, depth + 1)
                    if c.kind == "eoa":
                        n.notes.append(f"controlled by an EOA {ctl}: one private key, no timelock, no multisig")
                    elif c.kind == "safe" and c.safe_threshold == 1:
                        n.notes.append(f"controlled by a 1-of-N Safe {ctl}")
                    elif c.kind in ("safe", "contract", "proxy") and n.kind in ("proxy", "contract"):
                        n.notes.append(f"no recognised timelock between {ctl} and this contract (OZ TimelockController or Compound Timelock)")
        return n


def describe(n: Node) -> str:
    bits = [f"{n.address}: {n.kind}"]
    if n.implementation:
        bits.append(f"impl={n.implementation}")
    if n.proxy_admin:
        bits.append(f"proxyAdmin={n.proxy_admin}")
    if n.beacon:
        bits.append(f"beacon={n.beacon}")
    if n.owner:
        bits.append(f"owner={n.owner}")
    if n.pending_owner:
        bits.append(f"pendingOwner={n.pending_owner}")
    if n.admin and n.admin != n.proxy_admin:
        bits.append(f"admin={n.admin}")
    if n.safe_threshold is not None:
        bits.append(f"safe {n.safe_threshold}-of-{len(n.safe_owners)}")
    if n.delay is not None:
        bits.append(f"delay={n.delay}s")
    if n.paused is not None:
        bits.append(f"paused={n.paused}")
    if n.open_executor is not None:
        bits.append(f"openExecutor={n.open_executor}")
    s = "  ".join(bits)
    for role, holders in n.roles.items():
        s += f"\n    {role}: {', '.join(holders)}"
    for note in n.notes:
        s += f"\n    ! {note}"
    return s


def suggest_config(prober: Prober, rpc_url: str, chain_name: str, safe_chain: str | None, label: str) -> str:
    contracts, safes = [], []
    for n in prober.seen.values():
        if n.kind == "eoa":
            continue
        what = {"safe": "Safe", "timelock": "Timelock", "legacy-timelock": "Timelock", "proxy": "Proxy"}.get(n.kind, "Contract")
        contracts.append({"address": n.address, "label": f"{label} {what}"})
        if n.kind == "safe" and safe_chain:
            safes.append({"address": n.address, "label": f"{label} Safe", "chain": safe_chain})
    cfg = {"rpc_url": rpc_url, "chain_name": chain_name, "confirmations": 2, "max_block_range": 2000,
           "contracts": contracts}
    if safes:
        cfg["safes"] = safes
    cfg["alerts"] = {"discord_webhook": ""}
    return yaml.safe_dump(cfg, sort_keys=False)
