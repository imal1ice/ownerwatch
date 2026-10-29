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
# Free public RPCs that serve full log history (verified 2026-10-15); used for
# role replay when no --logs-rpc is given. Ranges are still split adaptively.
PUBLIC_LOG_RPCS = {
    1: "https://mainnet.gateway.tenderly.co",
    10: "https://optimism.gateway.tenderly.co",
    100: "https://gnosis.gateway.tenderly.co",
    137: "https://polygon.gateway.tenderly.co",
    8453: "https://base.gateway.tenderly.co",
    42161: "https://arbitrum.gateway.tenderly.co",
}
MULTICALL3_ABI = [{"type": "function", "name": "aggregate3", "stateMutability": "payable",
                   "inputs": [{"name": "calls", "type": "tuple[]", "components": [
                       {"name": "target", "type": "address"}, {"name": "allowFailure", "type": "bool"}, {"name": "callData", "type": "bytes"}]}],
                   "outputs": [{"name": "returnData", "type": "tuple[]", "components": [
                       {"name": "success", "type": "bool"}, {"name": "returnData", "type": "bytes"}]}]}]


SOLADY_ERC1967_FACTORY = "0x0000000000006396FF2a80c067f99B3d2Ab4Df24"   # canonical, same address on every chain


def _sel(sig: str) -> bytes:
    return Web3.keccak(text=sig)[:4]


def _embedded_addresses(code: bytes, limit: int = 8) -> list[str]:
    """Addresses pushed as constants in runtime bytecode: PUSH20, or PUSH32 with 12 leading
    zero bytes (Solidity immutables). Factory-deployed proxies (Solady ERC1967Factory and
    forks) embed the factory this way, and the factory, not the proxy, stores the admin."""
    out: list[str] = []
    i = 0
    while i < len(code) and len(out) < limit:
        op = code[i]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            data = code[i + 1:i + 1 + n]
            raw = data if n == 20 else (data[12:] if n == 32 and data[:12] == b"\x00" * 12 else None)
            if raw is not None and len(raw) == 20 and raw != b"\x00" * 20 and raw != b"\xff" * 20:
                a = Web3.to_checksum_address("0x" + raw.hex())
                if a not in out:
                    out.append(a)
            i += 1 + n
        else:
            i += 1
    return out


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
    admin_factory: str | None = None    # set when the upgrade admin is stored in a proxy factory (adminOf)
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

    def role_names(self, addr: str) -> dict[str, str]:
        """Map role hashes to names by calling every zero-argument bytes32 getter
        in the contract's verified ABI (or its implementation's): MINTER_ROLE(), etc."""
        from .decode import implementation_of, verified_abi
        addr = Web3.to_checksum_address(addr)
        try:
            chain_id = self.w3.eth.chain_id
            abi = verified_abi(chain_id, addr)
            if not abi:
                impl = implementation_of(self.w3, addr)
                abi = verified_abi(chain_id, impl) if impl else None
        except Exception:  # noqa: BLE001
            abi = None
        getters = [f["name"] for f in abi or [] if f.get("type") == "function" and not f.get("inputs")
                   and len(f.get("outputs") or []) == 1 and f["outputs"][0]["type"] == "bytes32"
                   and f.get("stateMutability") in ("view", "pure")]
        if not getters:
            return {}
        results = self._batch_calls([(addr, _sel(f"{g}()")) for g in getters])
        return {"0x" + r.hex(): g for g, r in zip(getters, results) if r and len(r) == 32}

    def creation_block(self, addr: str) -> int:
        """Block the contract was deployed in: from Sourcify's verified deployment
        record, else a binary search over eth_getCode (archive RPC), else 0."""
        addr = Web3.to_checksum_address(addr)
        try:
            import requests
            r = requests.get(f"https://sourcify.dev/server/v2/contract/{self.w3.eth.chain_id}/{addr}",
                             params={"fields": "deployment"}, timeout=8)
            if r.ok:
                b = (r.json().get("deployment") or {}).get("blockNumber")
                if b:
                    return int(b)
        except Exception:  # noqa: BLE001
            pass
        lo, hi = 0, self.w3.eth.block_number
        try:
            if not self.w3.eth.get_code(addr, hi):
                return 0
            while lo < hi:
                mid = (lo + hi) // 2
                if self.w3.eth.get_code(addr, mid):
                    hi = mid
                else:
                    lo = mid + 1
            return lo
        except Exception:  # noqa: BLE001
            return 0          # non-archive RPC: scan from genesis

    def _get_logs_split(self, params: dict, from_block: int, to_block: int, w3: Web3 | None = None,
                        budget: int = 2000, log=None) -> list:
        """Adaptive chunked eth_getLogs for free RPCs: start with the whole range,
        halve the chunk on a range error and remember the ceiling, grow back after
        successes, wait out rate limits. budget caps the request count."""
        w3 = w3 or self.w3
        out: list = []
        start, chunk, ceiling, requests_made = from_block, to_block - from_block + 1, None, 0
        while start <= to_block:
            end = min(start + chunk - 1, to_block)
            requests_made += 1
            if requests_made > budget:
                raise RuntimeError(f"eth_getLogs budget of {budget} requests exhausted at block {start}")
            try:
                out += w3.eth.get_logs({**params, "fromBlock": start, "toBlock": end})
            except Exception as e:  # noqa: BLE001
                msg = str(e).lower()
                if "429" in msg or "rate limit" in msg or "too many requests" in msg:
                    import time
                    time.sleep(2)
                    continue
                if chunk <= 50 or not any(k in msg for k in ("range", "limit", "exceed", "large", "span", "many", "more than", "results")):
                    raise          # pruned history, auth, method missing: smaller chunks will not help
                ceiling = chunk // 2
                chunk = ceiling
                continue
            start = end + 1
            if ceiling is None or chunk * 2 <= ceiling:
                chunk *= 2
            if log:
                log(f"  logs {start - from_block}/{to_block - from_block + 1} blocks, chunk {chunk}")
        return out

    def role_history(self, addr: str, from_block: int | None = None, logs_w3: Web3 | None = None,
                     log=None, to_block: int | None = None) -> dict[str, list[str]]:
        """Replay RoleGranted/RoleRevoked logs to list current holders per role.
        Scans from the creation block (Sourcify or code binary search) unless
        from_block is given; logs_w3 can be a different RPC that serves wide log
        ranges (e.g. the Tenderly public gateways, full history in one call) while self.w3 does the reads."""
        addr = Web3.to_checksum_address(addr)
        granted = _norm(topic0("RoleGranted(bytes32,address,address)"))
        revoked = _norm(topic0("RoleRevoked(bytes32,address,address)"))
        if from_block is None:
            from_block = self.creation_block(addr)
            if log:
                log(f"  {addr}: scanning role logs from block {from_block}")
        params = {"address": addr, "topics": [[granted, revoked]]}
        if logs_w3 is None and self.w3.eth.chain_id in PUBLIC_LOG_RPCS:
            try:
                public = Web3(Web3.HTTPProvider(PUBLIC_LOG_RPCS[self.w3.eth.chain_id], request_kwargs={"timeout": 60}))
                logs = self._get_logs_split(params, from_block, to_block or public.eth.block_number, w3=public, log=log)
            except Exception as e:  # noqa: BLE001
                if log:
                    log(f"  public log gateway failed ({e}); falling back to --rpc")
                logs = self._get_logs_split(params, from_block, to_block or self.w3.eth.block_number, log=log)
        else:
            logs = self._get_logs_split(params, from_block, to_block or (logs_w3 or self.w3).eth.block_number, w3=logs_w3, log=log)
        logs.sort(key=lambda l: (l["blockNumber"], l["logIndex"]))
        names = {("0x" + bytes(v).hex()): k for k, v in ROLES.items()}
        names.update(self.role_names(addr))
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
                try:
                    c = self.probe(who, depth=2)
                except Exception as e:  # noqa: BLE001
                    if log:
                        log(f"  could not classify {who}: {e}")
                    continue
                note = None
                if c.kind == "eoa":
                    note = f"DEFAULT_ADMIN_ROLE held by EOA {who}"
                elif c.kind == "safe" and c.safe_threshold == 1:
                    note = f"DEFAULT_ADMIN_ROLE held by 1-of-N Safe {who}"
                if note and note not in n.notes:
                    n.notes.append(note)
        return out

    def _slot_addr(self, addr: str, slot: int) -> str | None:
        v = self.w3.eth.get_storage_at(addr, slot)
        a = Web3.to_checksum_address("0x" + bytes(v)[-20:].hex())
        return None if a == ZERO else a

    def _factory_admin(self, proxy: str, code: bytes) -> tuple[str | None, str | None]:
        """For a proxy with an implementation but an empty ERC-1967 admin slot, ask every factory
        embedded in its bytecode (and Solady's canonical factory) for adminOf(proxy)."""
        cands = _embedded_addresses(code)
        if SOLADY_ERC1967_FACTORY not in cands:
            cands.append(SOLADY_ERC1967_FACTORY)
        data = _sel("adminOf(address)") + bytes(12) + bytes.fromhex(proxy[2:])
        for f in cands:
            if f == proxy:
                continue
            try:
                if len(self.w3.eth.get_code(f)) == 0:
                    continue
                r = bytes(self.w3.eth.call({"to": f, "data": data}))
            except Exception:  # noqa: BLE001
                continue
            if len(r) == 32 and r[:12] == bytes(12):
                a = Web3.to_checksum_address("0x" + r[12:].hex())
                if a != ZERO:
                    return a, f
        return None, None

    def _immutable_admin(self, proxy: str, code: bytes) -> str | None:
        """Aave's immutable-admin proxies keep the admin in their bytecode and answer admin() only to the admin
        (anyone else falls through to the implementation). Ask as each embedded address: the one the proxy
        answers with itself is the admin."""
        data = _sel("admin()")
        for cand in _embedded_addresses(code):
            if cand == proxy:
                continue
            try:
                r = bytes(self.w3.eth.call({"from": cand, "to": proxy, "data": data}))
            except Exception:  # noqa: BLE001
                continue
            if len(r) == 32 and r[:12] == bytes(12) and Web3.to_checksum_address("0x" + r[12:].hex()) == cand:
                return cand
        return None

    def _executor_delay(self, address: str) -> int | None:
        """Aave Governance V3 PayloadsController: the delay is per executor, in getExecutorSettingsByAccessControl.
        The shortest one is how fast this controller can act."""
        delays = []
        for level in (1, 2):
            try:
                r = bytes(self.w3.eth.call({"to": address, "data": _sel("getExecutorSettingsByAccessControl(uint8)") + level.to_bytes(32, "big")}))
            except Exception:  # noqa: BLE001
                continue
            if len(r) >= 64 and r[12:32] != bytes(20):
                delays.append(int.from_bytes(r[32:64], "big"))
        return min(delays) if delays else None

    def _timelocked(self, n: Node, hops: int = 2) -> bool:
        """A node acts through a timelock: it is one, or every controller it has (upgrade admin, owner(), admin())
        is, within a few hops. Aave's PoolAddressesProvider is owned by an executor that the PayloadsController owns."""
        if n.kind in ("timelock", "legacy-timelock"):
            return True
        if hops == 0 or n.kind in ("eoa", "safe"):
            return False
        ctls = {a for a in (n.proxy_admin, n.owner, n.admin) if a and a != n.address}
        return bool(ctls) and all(self._timelocked(self.seen.get(a) or self.probe(a, depth=2), hops - 1) for a in ctls)

    # ---- probe ----
    def probe(self, address: str, depth: int = 0) -> Node:
        address = Web3.to_checksum_address(address)
        if address in self.seen:
            return self.seen[address]
        n = Node(address=address)
        self.seen[address] = n
        code = bytes(self.w3.eth.get_code(address))
        n.code_size = len(code)
        if n.code_size == 0:
            n.kind = "eoa"
            return n
        n.implementation = self._slot_addr(address, IMPL_SLOT)
        n.proxy_admin = self._slot_addr(address, ADMIN_SLOT)
        n.beacon = self._slot_addr(address, BEACON_SLOT)
        if n.implementation and not n.proxy_admin and not n.beacon:
            n.proxy_admin, n.admin_factory = self._factory_admin(address, code)
            if not n.proxy_admin:
                n.proxy_admin = self._immutable_admin(address, code)
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
        d = self._uint(address, "getMinDelay()")      # OpenZeppelin TimelockController
        if d is None:
            d = self._uint(address, "getDelay()")     # Aave Governance V3 executors and similar
        if d is None:
            d = self._uint(address, "minDelay()")     # Solady Timelock
        if d is None:
            d = self._executor_delay(address)         # Aave Governance V3 PayloadsController
        if d is not None and n.kind == "unknown":
            n.kind = "timelock"
            n.delay = d
        legacy = self._uint(address, "delay()")
        legacy_admin = self._addr(address, "admin()")
        if legacy is not None and legacy_admin and n.kind == "unknown":
            n.kind = "legacy-timelock"            # Compound-style: delay() + admin()
            n.delay = legacy
            n.admin = legacy_admin
        elif (legacy is not None and n.kind == "unknown" and not n.implementation and not n.beacon
              and legacy <= 90 * 86400 and self._addr(address, "owner()")):
            n.kind = "timelock"                   # custom Ownable timelock: delay() + owner()
            n.delay = legacy
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
            links: dict[str, list[str]] = {}
            if n.proxy_admin and n.proxy_admin != address:
                links.setdefault(n.proxy_admin, []).append("upgrade admin")
            if n.owner and n.owner != address:
                links.setdefault(n.owner, []).append("owner()")
            if n.admin and n.admin != address and n.admin != n.proxy_admin:
                links.setdefault(n.admin, []).append("admin()")
            for ctl, roles in links.items():
                c = self.probe(ctl, depth + 1)
                what = " and ".join(roles)
                if c.kind == "eoa":
                    n.notes.append(f"{what} is an EOA {ctl}: one private key, no timelock, no multisig")
                elif c.kind == "safe" and c.safe_threshold == 1:
                    n.notes.append(f"{what} is a 1-of-N Safe {ctl}")
                elif c.kind in ("safe", "contract", "proxy") and n.kind in ("proxy", "contract") and not self._timelocked(c):
                    if roles == ["owner()"] and n.proxy_admin and n.proxy_admin != ctl:
                        n.notes.append(f"owner() is {ctl} with no timelock: owner-level settings change immediately "
                                       f"(upgrades are separate, via {n.proxy_admin})")
                    else:
                        n.notes.append(f"{what} is {ctl} with no recognised timelock in between")
        return n


def describe(n: Node) -> str:
    bits = [f"{n.address}: {n.kind}"]
    if n.implementation:
        bits.append(f"impl={n.implementation}")
    if n.proxy_admin:
        bits.append(f"proxyAdmin={n.proxy_admin}" + (f" (via factory {n.admin_factory})" if n.admin_factory else ""))
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
