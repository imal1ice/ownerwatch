"""Inspect an address's admin surface: proxy slots, owner/admin, Safe
owners and threshold, timelock delay. Classifies each controlling address
and suggests an ownerwatch config. Read-only; works on any EVM chain."""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml
from web3 import Web3

from .events import _norm, topic0

IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16)
BEACON_SLOT = int("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16)
ZERO = "0x" + "00" * 20
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"   # same address on every major EVM chain
MULTICALL3_ABI = [{"type": "function", "name": "aggregate3", "stateMutability": "payable",
                   "inputs": [{"name": "calls", "type": "tuple[]", "components": [
                       {"name": "target", "type": "address"}, {"name": "allowFailure", "type": "bool"}, {"name": "callData", "type": "bytes"}]}],
                   "outputs": [{"name": "returnData", "type": "tuple[]", "components": [
                       {"name": "success", "type": "bool"}, {"name": "returnData", "type": "bytes"}]}]}]


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
        self._mc = None
        try:
            if len(self.w3.eth.get_code(MULTICALL3)) > 0:
                self._mc = self.w3.eth.contract(address=MULTICALL3, abi=MULTICALL3_ABI)
        except Exception:  # noqa: BLE001
            self._mc = None

    def _batch_calls(self, calls: list[tuple[str, bytes]]) -> list[bytes | None]:
        """eth_call many (target, data) pairs in one request via Multicall3; falls back to one call each."""
        if self._mc is not None and len(calls) > 1:
            try:
                res = self._mc.functions.aggregate3([(t, True, d) for t, d in calls]).call()
                return [bytes(r[1]) if r[0] and r[1] else None for r in res]
            except Exception:  # noqa: BLE001
                pass
        out = []
        for t, d in calls:
            try:
                r = self.w3.eth.call({"to": t, "data": d})
                out.append(bytes(r) if r else None)
            except Exception:  # noqa: BLE001
                out.append(None)
        return out

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
        contracts = [n for n in self.seen.values() if n.kind != "eoa"]
        # one batched request to find which contracts speak AccessControl at all
        probe_calls = [(n.address, _sel("hasRole(bytes32,address)") + ROLES["DEFAULT_ADMIN_ROLE"] + bytes(32)) for n in contracts]
        supports = self._batch_calls(probe_calls)
        for n, sup in zip(contracts, supports):
            if sup is None or len(sup) != 32:
                continue
            pairs = [(name, c) for name in ROLES for c in candidates if c != n.address]
            if n.kind == "timelock":
                pairs.append(("EXECUTOR_ROLE", ZERO))
            calls = [(n.address, _sel("hasRole(bytes32,address)") + ROLES[name] + bytes(12) + bytes.fromhex(c[2:])) for name, c in pairs]
            results = self._batch_calls(calls)
            for (name, c), r in zip(pairs, results):
                has = bool(int.from_bytes(r[:32], "big")) if r and len(r) == 32 else False
                if not has:
                    continue
                if c == ZERO:
                    n.open_executor = True
                    n.notes.append("executor role is open: anyone can execute a matured operation")
                else:
                    n.roles.setdefault(name, []).append(c)
            if n.kind == "timelock" and n.open_executor is None:
                n.open_executor = False
            for who in n.roles.get("DEFAULT_ADMIN_ROLE", []):
                c = self.seen.get(who)
                if c and c.kind == "eoa":
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by EOA {who}")
                elif c and c.kind == "safe" and c.safe_threshold == 1:
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by 1-of-N Safe {who}")

    def _get_logs_split(self, params: dict, from_block: int, to_block: int) -> list:
        try:
            return self.w3.eth.get_logs({**params, "fromBlock": from_block, "toBlock": to_block})
        except Exception:  # noqa: BLE001
            if to_block - from_block < 200:
                raise
            mid = (from_block + to_block) // 2
            return self._get_logs_split(params, from_block, mid) + self._get_logs_split(params, mid + 1, to_block)

    def role_history(self, addr: str, from_block: int = 0) -> dict[str, list[str]]:
        """Replay RoleGranted/RoleRevoked logs to list current holders per role.
        Needs an RPC that serves historical logs; wide ranges are split on error."""
        addr = Web3.to_checksum_address(addr)
        granted = _norm(topic0("RoleGranted(bytes32,address,address)"))
        revoked = _norm(topic0("RoleRevoked(bytes32,address,address)"))
        logs = self._get_logs_split({"address": addr, "topics": [[granted, revoked]]}, from_block, self.w3.eth.block_number)
        logs.sort(key=lambda l: (l["blockNumber"], l["logIndex"]))
        names = {("0x" + bytes(v).hex()): k for k, v in ROLES.items()}
        holders: dict[str, set[str]] = {}
        for lg in logs:
            t0 = "0x" + bytes(lg["topics"][0]).hex()
            role = "0x" + bytes(lg["topics"][1]).hex()
            who = Web3.to_checksum_address("0x" + bytes(lg["topics"][2])[-20:].hex())
            name = names.get(role, role)
            if t0 == granted:
                holders.setdefault(name, set()).add(who)
            else:
                holders.get(name, set()).discard(who)
        out = {k: sorted(v) for k, v in holders.items() if v}
        n = self.seen.get(addr)
        if n is not None:
            for k, v in out.items():
                n.roles[k] = v
            for who in out.get("DEFAULT_ADMIN_ROLE", []):
                c = self.probe(who, depth=2)
                if c.kind == "eoa":
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by EOA {who}")
                elif c.kind == "safe" and c.safe_threshold == 1:
                    n.notes.append(f"DEFAULT_ADMIN_ROLE held by 1-of-N Safe {who}")
        return out

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
        if d is None:
            d = self._uint(address, "getDelay()")   # Aave Governance V3 executors and similar
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


def markdown_report(prober: Prober, label: str, chain_name: str, roots: list[Node]) -> str:
    """A short admin-surface report a protocol team can read in two minutes."""
    def short(a: str) -> str:
        return a[:6] + "…" + a[-4:]

    lines = [f"# {label} admin surface on {chain_name}", ""]
    lines += ["| Address | Type | Controlled by | Detail |", "|---|---|---|---|"]
    for n in prober.seen.values():
        if n.kind == "eoa":
            continue
        ctl = n.proxy_admin or n.owner or n.admin or "-"
        detail = []
        if n.safe_threshold is not None:
            detail.append(f"{n.safe_threshold}-of-{len(n.safe_owners)}")
        if n.delay is not None:
            detail.append(f"{n.delay // 3600}h delay")
        if n.implementation:
            detail.append(f"impl {short(n.implementation)}")
        if n.open_executor:
            detail.append("open executor")
        if n.paused:
            detail.append("PAUSED")
        for role, holders in n.roles.items():
            detail.append(f"{role}: " + ", ".join(short(h) for h in holders))
        lines.append(f"| `{short(n.address)}` | {n.kind} | `{short(ctl) if ctl != '-' else '-'}` | {'; '.join(detail) or '-'} |")
    risks = [(n.address, note) for n in prober.seen.values() for note in n.notes]
    lines += ["", "## Findings", ""]
    if risks:
        for a, note in risks:
            lines.append(f"- `{short(a)}`: {note}")
    else:
        lines.append("- No single-key or zero-delay control paths found among the probed addresses.")
    chain_summary = []
    for r in roots:
        path, cur, hops = [r], r, 0
        while hops < 3:
            nxt = cur.proxy_admin or cur.owner or cur.admin
            if not nxt or nxt == cur.address or nxt not in prober.seen:
                break
            cur = prober.seen[nxt]
            path.append(cur)
            hops += 1
        chain_summary.append(" -> ".join(f"{short(x.address)} ({x.kind}{'' if x.safe_threshold is None else f' {x.safe_threshold}-of-{len(x.safe_owners)}'}{'' if x.delay is None else f' {x.delay // 3600}h'})" for x in path))
    lines += ["", "## Control paths", ""] + [f"- {c}" for c in chain_summary]
    lines += ["", "## What ownerwatch would alert on", "",
              "Owner, proxy admin and implementation changes; Safe signer and threshold changes and every queued Safe transaction before it executes; "
              "timelock schedules with the decoded call; role grants and revokes; pauses; large treasury outflows.", "",
              f"_Generated by `ownerwatch probe` on {chain_name}. Read-only; nothing was sent on-chain._"]
    return "\n".join(lines) + "\n"
