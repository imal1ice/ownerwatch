"""Inspect an address's admin surface: proxy slots, owner/admin, Safe
owners and threshold, timelock delay. Classifies each controlling address
and suggests an ownerwatch config. Read-only; works on any EVM chain."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import requests
import yaml
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.middleware import ExtraDataToPOAMiddleware

from . import __version__
from .alerts import redact
from .events import _norm, topic0

IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16)
BEACON_SLOT = int("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16)
# Older layouts still in use: ZeppelinOS (USDC among others) and EIP-1822 UUPS drafts
LEGACY_IMPL_SLOTS = (int.from_bytes(Web3.keccak(text="org.zeppelinos.proxy.implementation"), "big"),
                     int.from_bytes(Web3.keccak(text="PROXIABLE"), "big"))
LEGACY_ADMIN_SLOT = int.from_bytes(Web3.keccak(text="org.zeppelinos.proxy.admin"), "big")
ZERO = "0x" + "00" * 20
MAX_NODES = 400     # a bound on how far the walk up the controllers goes, for pathological graphs only
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
# Sky (MakerDAO) governance acts through this proxy, which the DSPause controls; contracts authorise it as a ward.
SKY_PAUSE_PROXY = "0xBE8E3e3618f7474F8cB1d074A26afFef007E98FB"


EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
AM_PUBLIC_ROLE = 2**64 - 1
EIP7702_PREFIX = bytes.fromhex("ef0100")
# Operational keys that are not upgrade or ownership paths but control assets or pricing directly
NAMED_GETTERS = {
    "fundsHolder()": "fundsHolder() (receives deposits)",
    "safe()": "safe() (holds the vault's assets)",
    "valuationManager()": "valuationManager() (sets the NAV)",
    "curator()": "curator()",
    "guardian()": "guardian()",
}
# Selectors checked on AccessManaged targets when no verified ABI is available
AM_FALLBACK_FNS = ["upgradeToAndCall(address,bytes)", "setAuthority(address)", "pause()", "unpause()",
                   "mint(address,uint256)", "transferOwnership(address)"]
# Functions that must not be open to everyone. A public deposit() is normal, and so are a vault's ERC-4626
# mint(uint256,address) and withdraw(uint256,address,address); a public upgradeToAndCall() is not.
AM_SENSITIVE_FN = re.compile(r"^(upgrade|setAuthority|transferOwnership|renounceOwnership|grantRole|revokeRole|setOwner|setImplementation)|^mint\(address,uint256\)$", re.I)
AM_ROLE_PREFIX = "accessManager:"
LONG_DELAY = 86400   # an execution or admin delay at least this long leaves time to react; shorter ones are reported
# delay() or owner() alone do not make a timelock: plenty of contracts have a parameter called delay.
TIMELOCK_FNS = [
    "queueTransaction(address,uint256,string,bytes,uint256)", "executeTransaction(address,uint256,string,bytes,uint256)",
    "cancelTransaction(address,uint256,string,bytes,uint256)", "queuedTransactions(bytes32)", "GRACE_PERIOD()", "getGracePeriod()",
    "queueTransaction(address,uint256,string,bytes,uint256,bool)", "executeTransaction(address,uint256,string,bytes,uint256,bool)",
    "isActionQueued(bytes32)", "queue(uint256)", "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
    "execute(address,uint256,bytes,bytes32,bytes32)", "propose(bytes,bytes32,bytes32)", "execute(bytes32,bytes)", "getOperationState(bytes32)",
    "isOperation(bytes32)", "cancel(bytes32)", "propose(bytes32,bytes,uint256)", "operationState(bytes32)", "readyTimestamp(bytes32)",
    "MIN_DELAY()", "scheduledAt(bytes32)",
]
TIMELOCK_FN_NAME = re.compile(r"queue|schedule|propose", re.I)
# How RPC nodes report a call that reverted or hit bad code. Everything else means the read itself failed.
_REVERT_WORDS = ("revert", "vm execution", "evm error", "evmerror", "opcode", "out of gas", "not enough gas", "gas required exceeds",
                 "stack underflow", "stack overflow", "stack limit", "invalid jump", "bad jump", "bad instruction", "execution error", "precompile")

# ---- proving findings by simulation (--prove) ----
# A privileged call that succeeds from the holder and reverts from a stranger proves the holder controls it. Nothing is
# sent: eth_call only, at one pinned block, with safe dummy arguments that are never committed. A call that reverts from
# both the holder and the stranger is gated by state, not the caller, so it proves nothing and is never reported proven.
STRANGER = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
DUMMY_ADDR = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")   # nonzero: a zero address trips sanity checks
DUMMY_SALT = bytes(31) + b"\x01"
OWNER_FNS = {"transferOwnership(address)": ["address"], "setOwner(address)": ["address"],
             "setPeer(uint32,bytes32)": ["uint32", "bytes32"], "setDelegate(address)": ["address"]}   # onlyOwner functions, tried in order: first present is simulated
# upgradeTo first: on zos/older transparent proxies it is a clean admin-only call, while upgradeToAndCall(impl, "") can
# self-call and revert. UUPS proxies have only upgradeToAndCall, so they fall through to it (empty data makes no call).
UPGRADE_FNS = {"upgradeTo(address)": ["address"], "upgradeToAndCall(address,bytes)": ["address", "bytes"]}
SCHEDULE_FN = "schedule(address,uint256,bytes,bytes32,bytes32,uint256)"    # OpenZeppelin TimelockController
MINT_FN_NAME = re.compile(r"^(mint|issue)", re.I)
SIMPLE_ARG = re.compile(r"^(address|bool|string|bytes\d*|u?int\d*)$")


class ProbeRpcError(RuntimeError):
    """A read failed for a reason other than the contract reverting. The report cannot be trusted past this point."""


def _is_revert(e: Exception) -> bool:
    if isinstance(e, ContractLogicError):
        return True
    if isinstance(e, (requests.RequestException, OSError)):
        return False
    msg = str(e).lower()
    return any(w in msg for w in _REVERT_WORDS)


def _word_addr(word: bytes) -> str | None:
    """The address in a 32-byte word, or None when the word cannot be one: dirty high bytes (a bytes32 or a hash),
    or a value so small it is a bool, a count, a duration or a string offset rather than a key."""
    if len(word) != 32 or word[:12] != bytes(12) or int.from_bytes(word, "big") < 2**64:
        return None
    return Web3.to_checksum_address("0x" + word[12:].hex())


def _pad(addr: str) -> bytes:
    return bytes(12) + bytes.fromhex(addr[2:])


def _dur(seconds: int) -> str:
    """A delay in the largest whole units: 1800 -> 30m, 90000 -> 25h."""
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds >= 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 60}m" if seconds % 60 == 0 else f"{seconds}s"


def make_w3(url: str, timeout: int = 30) -> Web3:
    """A Web3 client that also reads blocks on chains with long extraData (Polygon, BSC and other PoA chains)."""
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    # web3 validates every eth_call against the chain id and asks the node for it each time: over half of a long
    # probe's requests. The chain id of an RPC URL does not change, so it is the one answer kept.
    w3.provider.cache_allowed_requests = True
    w3.provider.cacheable_requests = {"eth_chainId"}
    return w3


def _abi_type(i: dict) -> str:
    """Canonical type of an ABI input, expanding tuples: (address,bytes)[]."""
    t = i["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_abi_type(c) for c in i.get("components") or []) + ")" + t[5:]
    return t


def _clone_target(code: bytes) -> str | None:
    """Implementation of an EIP-1167 minimal proxy, from its 45-byte runtime code."""
    if len(code) == 45 and code[:10] == EIP1167_PREFIX and code[30:] == EIP1167_SUFFIX:
        return Web3.to_checksum_address("0x" + code[10:30].hex())
    return None


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
    "ADMIN_ROLE": Web3.keccak(text="ADMIN_ROLE"),
    "PROPOSER_ROLE": Web3.keccak(text="PROPOSER_ROLE"),
    "EXECUTOR_ROLE": Web3.keccak(text="EXECUTOR_ROLE"),
    "CANCELLER_ROLE": Web3.keccak(text="CANCELLER_ROLE"),
    "UPGRADER_ROLE": Web3.keccak(text="UPGRADER_ROLE"),
    "PAUSER_ROLE": Web3.keccak(text="PAUSER_ROLE"),
    "MINTER_ROLE": Web3.keccak(text="MINTER_ROLE"),
}


@dataclass
class Proof:
    """A finding backed by a simulation: `fn` run as an eth_call at the pinned block. `proven` is True only when the
    call succeeds from `holder` and reverts from a stranger; otherwise `why` says why control could not be simulated."""
    fn: str                   # the privileged function simulated, e.g. transferOwnership(address)
    role: str                 # what the holder is: owner(), DEFAULT_ADMIN_ROLE, upgrade admin, PROPOSER_ROLE
    holder: str | None        # the address the call succeeds from (a finding's EOA or Safe)
    proven: bool
    why: str = ""             # when not proven, why the simulation does not prove control

    def line(self, short=lambda a: a) -> str:
        who = f"{self.role} {short(self.holder)}" if self.holder else self.role
        if self.proven:
            return f"proven: {self.fn} succeeds from {who}, reverts from a stranger"
        return f"not simulated: {self.fn} ({who}): {self.why}" if self.holder else f"not simulated: {self.fn}: {self.why}"


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
    admin_getter: str = "admin()"       # which getter named the admin: some UUPS proxies expose getAdmin() instead
    safe_threshold: int | None = None
    safe_owners: list[str] = field(default_factory=list)
    safe_modules: list[str] = field(default_factory=list)   # modules execute without the signers
    delay: int | None = None
    paused: bool | None = None
    roles: dict[str, list[str]] = field(default_factory=dict)   # role name -> holders found among probed addresses
    kernel: str | None = None           # Aragon app: the DAO kernel whose ACL grants upgrades and permissions
    authorizer: str | None = None       # Balancer-style getAuthorizer(), followed to the actual authorizer
    dao: str | None = None              # dao() (Curve admin contracts and similar)
    emergency: str | None = None        # emergency() (Curve)
    wards: list[str] = field(default_factory=list)   # DSAuth/Maker wards among the addresses tested
    open_executor: bool | None = None
    delegate: str | None = None         # EIP-7702: an EOA whose code delegates to this contract
    named: dict[str, str] = field(default_factory=dict)   # NAMED_GETTERS label -> address
    clone_of: str | None = None         # EIP-1167 minimal proxy: fixed implementation, not upgradeable by itself
    authority: str | None = None        # OpenZeppelin AccessManaged: the AccessManager that gates its functions
    am_roles: dict[int, list[tuple[str, int]]] = field(default_factory=dict)   # AccessManager: role id -> [(holder, execution delay)]
    am_role_admin: dict[int, int] = field(default_factory=dict)                # AccessManager: role id -> admin role id
    am_gates: dict[int, list[str]] = field(default_factory=dict)              # AccessManager: role id -> ["fn on 0xTarget"]
    am_grant_delay: dict[int, int] = field(default_factory=dict)              # AccessManager: role id -> seconds a grant waits
    am_target_delay: dict[str, int] = field(default_factory=dict)             # AccessManager: target -> seconds a guard change waits
    am_closed: list[str] = field(default_factory=list)                        # AccessManager: targets closed to every caller
    am_open: list[str] = field(default_factory=list)                          # AccessManager: sensitive functions open to anyone
    am_unmapped: list[str] = field(default_factory=list)                      # AccessManager: targets with no verified ABI
    notes: list[str] = field(default_factory=list)
    proofs: list[Proof] = field(default_factory=list)   # --prove: each finding backed (or not) by a simulation


class Prober:
    def __init__(self, w3: Web3):
        self.w3 = w3
        self.seen: dict[str, Node] = {}
        self.replayed: set[str] = set()      # addresses whose role logs were replayed
        self.incomplete: list[str] = []      # what this report could not cover; printed under Findings
        self._code_cache: dict[str, bytes] = {}
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
        return [self._eth_call({"to": t, "data": d}) for t, d in calls]

    # ---- low level ----
    def _eth_call(self, tx: dict) -> bytes | None:
        """None when the call reverts or returns nothing: the contract has no such function. A rate limit, pruned
        state or a dead RPC is a different thing, and reading it as "no such function" would turn a real owner
        into a clean report. Those are retried, then raised."""
        return self._try_call(tx) or None

    def _try_call(self, tx: dict) -> bytes | None:
        """Like _eth_call, but a call that succeeds with no return data (a mint() that returns nothing) is b"", not None."""
        for attempt in range(3):
            try:
                return bytes(self.w3.eth.call(tx))
            except Exception as e:  # noqa: BLE001
                if _is_revert(e):
                    return None
                if attempt == 2:
                    raise ProbeRpcError(f"RPC failed eth_call ({redact(e)}); use an RPC that supports reads, e.g. https://eth.drpc.org") from e
                time.sleep(attempt + 1)
        return None

    def _call(self, addr: str, sig: str) -> bytes | None:
        return self._eth_call({"to": addr, "data": _sel(sig)})

    def _call_args(self, addr: str, sig: str, args: bytes) -> bytes | None:
        return self._eth_call({"to": addr, "data": _sel(sig) + args})

    def _addr(self, addr: str, sig: str) -> str | None:
        r = self._call(addr, sig)
        return _word_addr(r) if r else None

    def _uint(self, addr: str, sig: str) -> int | None:
        r = self._call(addr, sig)
        return int.from_bytes(r[:32], "big") if r and len(r) >= 32 else None

    def _has_role(self, addr: str, role: bytes, who: str) -> bool | None:
        r = self._eth_call({"to": addr, "data": _sel("hasRole(bytes32,address)") + role + _pad(who)})
        return bool(int.from_bytes(r, "big")) if r and len(r) == 32 else None

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
            # AccessControlEnumerable lists its members: no need to guess candidates
            for name, role in ROLES.items():
                count = self._batch_calls([(n.address, _sel("getRoleMemberCount(bytes32)") + role)])[0]
                if not count or len(count) != 32:
                    break
                k = int.from_bytes(count, "big")
                calls = [(n.address, _sel("getRoleMember(bytes32,uint256)") + role + i.to_bytes(32, "big")) for i in range(min(k, 50))]
                members = [Web3.to_checksum_address("0x" + r[12:32].hex()) for r in self._batch_calls(calls) if r and len(r) == 32]
                for m in members:
                    if m not in n.roles.get(name, []):
                        n.roles.setdefault(name, []).append(m)
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
                elif c not in n.roles.get(name, []):
                    n.roles.setdefault(name, []).append(c)
            if n.kind == "timelock" and n.open_executor is None:
                n.open_executor = False
            self._role_findings(n)
        self._refine_notes()
        self.check_access_managers(candidates)

    def _role_findings(self, n: Node) -> None:
        """Powerful roles held outside any timelock: the "multisig, but no clock" case. A pause role on a Safe is
        left out on purpose: pausing without delay is what a guardian is for."""
        self._refine_notes()
        upgrade = self.seen.get(n.proxy_admin) if n.proxy_admin else None
        upgrade_delay = None
        if upgrade is not None and self._timelocked(upgrade):
            t = upgrade if upgrade.kind in ("timelock", "legacy-timelock") else self.seen.get(upgrade.owner or "")
            upgrade_delay = t.delay if t is not None and t.delay else None
        for role, holders in list(n.roles.items()):
            core = role in ("DEFAULT_ADMIN_ROLE", "MINTER_ROLE", "UPGRADER_ROLE")
            proposer = n.kind == "timelock" and role == "PROPOSER_ROLE"
            if not (core or proposer or re.search(r"ADMIN|UPGRAD|MINT", role)):
                continue
            for who in holders:
                if who == ZERO:     # no key signs for the zero address
                    continue
                c = self.seen.get(who) or self.probe(who)   # a holder found by enumeration or a candidate
                if c.kind == "eoa":
                    note = f"{role} held by EOA {who}" + (": this address alone can queue any change on this timelock" if proposer else "")
                elif c.kind == "safe" and c.safe_threshold == 1:
                    note = f"{role} held by 1-of-N Safe {who}"
                elif core and c.kind == "safe" and not self._timelocked(c):
                    note = (f"{role} held by {c.safe_threshold}-of-{len(c.safe_owners)} Safe {who} with no timelock: "
                            "it takes effect immediately")
                    if upgrade_delay:
                        note += f", while upgrades wait {_dur(upgrade_delay)}"
                else:
                    continue
                if note not in n.notes:
                    n.notes.append(note)
        executors = n.roles.get("EXECUTOR_ROLE", [])
        if n.kind == "timelock" and not n.open_executor and len(executors) == 1:
            if (self.seen.get(executors[0]) or self.probe(executors[0])).kind == "eoa":
                note = f"the only EXECUTOR_ROLE holder is EOA {executors[0]}: nothing queued can run without that address"
                if note not in n.notes:
                    n.notes.append(note)

    def _refine_notes(self) -> None:
        """Once role holders are known, drop the "no timelock" notes whose controller turns out to act through a
        timelock (an AccessControl contract whose DEFAULT_ADMIN_ROLE is a timelock, for instance)."""
        pat = re.compile(r" is (0x[0-9a-fA-F]{40}) with no (?:recognised )?timelock(?: in between$|: owner-level)")
        for n in list(self.seen.values()):
            keep = []
            for note in n.notes:
                m = pat.search(note)
                c = self.seen.get(m.group(1)) if m else None
                if c is None or not self._timelocked(c):
                    keep.append(note)
            n.notes = keep

    def role_names(self, addr: str) -> dict[str, str]:
        """Map role hashes to names by calling every zero-argument bytes32 getter
        in the contract's verified ABI (or its implementation's): MINTER_ROLE(), etc."""
        from .decode import implementation_of, verified_abi
        addr = Web3.to_checksum_address(addr)
        abi: list = []
        try:
            chain_id = self.w3.eth.chain_id
            impl = implementation_of(self.w3, addr)
            for a in (addr, impl):      # a verified proxy's own ABI says nothing about the roles behind it
                if a:
                    abi += verified_abi(chain_id, a) or []
        except Exception:  # noqa: BLE001
            pass
        getters = sorted({f["name"] for f in abi if f.get("type") == "function" and not f.get("inputs")
                          and len(f.get("outputs") or []) == 1 and f["outputs"][0]["type"] == "bytes32"
                          and f.get("stateMutability") in ("view", "pure")})
        if not getters:
            return {}
        results = self._batch_calls([(addr, _sel(f"{g}()")) for g in getters])
        # a getter returning zero is an unset value like merkleRoot(), not a name for DEFAULT_ADMIN_ROLE
        return {"0x" + r.hex(): g for g, r in zip(getters, results) if r and len(r) == 32 and any(r)}

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
        start, chunk, ceiling, requests_made, limited = from_block, to_block - from_block + 1, None, 0, 0
        while start <= to_block:
            end = min(start + chunk - 1, to_block)
            requests_made += 1
            if requests_made > budget:
                raise RuntimeError(f"eth_getLogs budget of {budget} requests exhausted at block {start}")
            try:
                out += w3.eth.get_logs({**params, "fromBlock": start, "toBlock": end})
            except Exception as e:  # noqa: BLE001
                msg = str(e).lower()
                if re.search(r"\b429\b|rate.?limit|too many requests", msg):
                    limited += 1
                    if limited > 8:
                        raise ProbeRpcError(f"eth_getLogs still rate limited after {limited} waits at block {start}") from e
                    time.sleep(min(2 ** limited, 30))
                    continue
                if chunk <= 50 or not any(k in msg for k in ("range", "limit", "exceed", "large", "span", "many", "more than", "results")):
                    raise          # pruned history, auth, method missing: smaller chunks will not help
                ceiling = chunk // 2
                chunk = ceiling
                continue
            start = end + 1
            limited = 0
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
        is_am = (self.seen.get(addr) or self.probe(addr)).kind == "access-manager"
        if is_am:
            granted = _norm(topic0("RoleGranted(uint64,address,uint32,uint48,bool)"))
            revoked = _norm(topic0("RoleRevoked(uint64,address)"))
            guards = _norm(topic0("TargetFunctionRoleUpdated(address,bytes4,uint64)"))
        else:
            granted = _norm(topic0("RoleGranted(bytes32,address,address)"))
            revoked = _norm(topic0("RoleRevoked(bytes32,address,address)"))
            guards = None
        if from_block is None:
            from_block = self.creation_block(addr)
            if log:
                log(f"  {addr}: scanning role logs from block {from_block}")
        params = {"address": addr, "topics": [[t for t in (granted, revoked, guards) if t]]}
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
        self.replayed.add(addr)
        if is_am:
            return self._am_replay(addr, logs, granted, guards)
        names = self.role_names(addr)
        names.update({("0x" + bytes(v).hex()): k for k, v in ROLES.items()})
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
            self._role_findings(n)
            self._refine_notes()
        return out

    def _am_replay(self, addr: str, logs: list, granted: str, guards: str) -> dict[str, list[str]]:
        """AccessManager role replay: every account ever granted a role, confirmed with hasRole now, and every
        target function ever given a role, confirmed with getTargetFunctionRole now. The second finds what a
        role guards on targets with no verified ABI."""
        seen_pairs: set[tuple[int, str]] = set()
        guarded: set[tuple[str, bytes]] = set()
        for lg in logs:
            t0 = "0x" + bytes(lg["topics"][0]).hex()
            if t0 == granted:
                seen_pairs.add((int.from_bytes(bytes(lg["topics"][1]), "big"),
                                Web3.to_checksum_address("0x" + bytes(lg["topics"][2])[-20:].hex())))
            elif t0 == guards:
                guarded.add((Web3.to_checksum_address("0x" + bytes(lg["topics"][1])[-20:].hex()), bytes(lg["data"])[:4]))
        m = self.seen[addr]
        self._am_map(m)
        ordered = sorted(guarded)
        calls = [(addr, _sel("getTargetFunctionRole(address,bytes4)") + _pad(t) + s + bytes(28)) for t, s in ordered]
        for (target, selector), r in zip(ordered, self._batch_calls(calls)):
            if not r or len(r) < 32:
                continue
            rid = int.from_bytes(r[:32], "big")
            if rid in (0, AM_PUBLIC_ROLE):     # a guard set back to the default, or opened up: mapped by _am_map when the ABI names it
                continue
            known = self.seen.get(target)
            names = {_sel(f): f.split("(")[0] for f in (self._am_target_fns(known)[0] if known else [])}
            label = f"{names.get(selector, '0x' + selector.hex())} on {target}"
            if not any(g == label for g in m.am_gates.get(rid, [])):
                m.am_gates.setdefault(rid, []).append(label)
        pairs = sorted(p for p in seen_pairs if p[1] != ZERO)    # a grant to the zero address gives no one the role
        now = int(time.time())
        for (r, who), res in zip(pairs, self._am_has_role(addr, pairs)):
            if res and res[0]:
                if all(h != who for h, _ in m.am_roles.get(r, [])):
                    m.am_roles.setdefault(r, []).append((who, res[1]))
                continue
            access = self._call_args(addr, "getAccess(uint64,address)", r.to_bytes(32, "big") + _pad(who))
            since = int.from_bytes(access[:32], "big") if access and len(access) >= 32 else 0
            if since > now:
                c = self.seen.get(who) or self.probe(who)
                note = f"pending grant: role {r} goes to {'EOA ' if c.kind == 'eoa' else ''}{who} at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(since))}"
                if note not in m.notes:
                    m.notes.append(note)
        ids = sorted(r for r in m.am_roles if r not in m.am_role_admin)
        for r, adm in zip(ids, self._batch_calls([(addr, _sel("getRoleAdmin(uint64)") + r.to_bytes(32, "big")) for r in ids])):
            if adm and len(adm) >= 32:
                m.am_role_admin[r] = int.from_bytes(adm[:32], "big")
        self._am_findings(m)
        return {f"role {r}": [h for h, _ in v] for r, v in m.am_roles.items()}

    def _slot_addr(self, addr: str, slot: int) -> str | None:
        return _word_addr(bytes(self.w3.eth.get_storage_at(addr, slot)))

    def _slots_addr(self, addr: str, *slots: int) -> str | None:
        for slot in slots:
            a = self._slot_addr(addr, slot)
            if a:
                return a
        return None

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
            if len(self.w3.eth.get_code(f)) == 0:
                continue
            r = self._eth_call({"to": f, "data": data})
            a = _word_addr(r) if r else None
            if a:
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
            r = self._eth_call({"from": cand, "to": proxy, "data": data})
            if r and _word_addr(r) == cand:
                return cand
        return None

    def _executor_delay(self, address: str) -> int | None:
        """Aave Governance V3 PayloadsController: the delay is per executor, in getExecutorSettingsByAccessControl.
        The shortest one is how fast this controller can act."""
        delays = []
        for level in (1, 2):
            r = self._call_args(address, "getExecutorSettingsByAccessControl(uint8)", level.to_bytes(32, "big"))
            if r and len(r) >= 64 and r[12:32] != bytes(20):
                delays.append(int.from_bytes(r[32:64], "big"))
        return min(delays) if delays else None

    # ---- OpenZeppelin AccessManager ----
    def _is_access_manager(self, addr: str) -> bool:
        return self._uint(addr, "ADMIN_ROLE()") == 0 and self._uint(addr, "PUBLIC_ROLE()") == AM_PUBLIC_ROLE

    def _am_has_role(self, am: str, pairs: list[tuple[int, str]]) -> list[tuple[bool, int] | None]:
        calls = [(am, _sel("hasRole(uint64,address)") + r.to_bytes(32, "big") + bytes(12) + bytes.fromhex(a[2:])) for r, a in pairs]
        out = []
        for res in self._batch_calls(calls):
            out.append((bool(int.from_bytes(res[:32], "big")), int.from_bytes(res[32:64], "big"))
                       if res and len(res) >= 64 else None)
        return out

    def _am_target_fns(self, t: Node) -> tuple[list[str], bool]:
        """Function signatures of an AccessManaged target that change state, from its verified ABI and its
        implementation's (a verified proxy's own ABI lists none of the functions behind it), plus a short list
        of common admin functions. The bool says whether any ABI was found."""
        from .decode import verified_abi
        abi: list = []
        try:
            chain_id = self.w3.eth.chain_id
            for a in (t.address, t.clone_of, t.implementation):
                if a:
                    abi += verified_abi(chain_id, a) or []
        except Exception:  # noqa: BLE001
            pass
        fns = [f"{f['name']}({','.join(_abi_type(i) for i in f.get('inputs') or [])})" for f in abi
               if f.get("type") == "function" and f.get("stateMutability") not in ("view", "pure")]
        return list(dict.fromkeys(fns + AM_FALLBACK_FNS)), bool(abi)

    def _am_targets(self, m: Node) -> list[Node]:
        """Contracts the manager can reach: those it gates through authority(), and those it owns or administers
        directly, whose onlyOwner functions it calls through execute()."""
        return [n for n in self.seen.values() if n.address != m.address and m.address in (n.authority, n.owner, n.proxy_admin, n.admin)]

    def _am_map(self, m: Node) -> set[int]:
        """Role ids of an AccessManager that matter for the targets seen: the roles guarding their functions,
        ADMIN_ROLE, and every role admin and guardian above them. Records which functions each role gates."""
        roles: set[int] = {0}
        for t in self._am_targets(m):
            fns, verified = self._am_target_fns(t)
            if not verified and t.address not in m.am_unmapped:
                m.am_unmapped.append(t.address)
            closed = self._call_args(m.address, "isTargetClosed(address)", _pad(t.address))
            if closed and any(closed):      # nobody can call anything on it, whatever the guards say
                if t.address not in m.am_closed:
                    m.am_closed.append(t.address)
                continue
            delay = self._call_args(m.address, "getTargetAdminDelay(address)", _pad(t.address))
            if delay and any(delay):
                m.am_target_delay[t.address] = int.from_bytes(delay[:32], "big")
            calls = [(m.address, _sel("getTargetFunctionRole(address,bytes4)") + _pad(t.address) + _sel(f) + bytes(28)) for f in fns]
            for f, r in zip(fns, self._batch_calls(calls)):
                if not r or len(r) < 32:
                    continue
                rid = int.from_bytes(r[:32], "big")
                label = f"{f.split('(')[0]} on {t.address}"
                if rid == AM_PUBLIC_ROLE:
                    if AM_SENSITIVE_FN.match(f) and label not in m.am_open:
                        m.am_open.append(label)
                    continue
                if rid == 0:     # every function nobody configured reads as ADMIN_ROLE, including ones that do not exist
                    continue
                roles.add(rid)
                if label not in m.am_gates.setdefault(rid, []):
                    m.am_gates[rid].append(label)
        frontier = set(roles)
        for _ in range(8):   # role admins (and guardians) of every role found, transitively
            if not frontier:
                break
            ids = sorted(frontier)
            res = self._batch_calls([(m.address, _sel("getRoleAdmin(uint64)") + r.to_bytes(32, "big")) for r in ids]
                                    + [(m.address, _sel("getRoleGuardian(uint64)") + r.to_bytes(32, "big")) for r in ids])
            new = set()
            for i, r in enumerate(ids):
                adm, grd = res[i], res[len(ids) + i]
                if adm and len(adm) >= 32:
                    a = int.from_bytes(adm[:32], "big")
                    m.am_role_admin[r] = a
                    if a not in roles and a != AM_PUBLIC_ROLE:
                        new.add(a)
                if grd and len(grd) >= 32:
                    g = int.from_bytes(grd[:32], "big")
                    if g not in roles and g not in (0, AM_PUBLIC_ROLE):
                        new.add(g)
            for r, gd in zip(ids, self._batch_calls([(m.address, _sel("getRoleGrantDelay(uint64)") + r.to_bytes(32, "big")) for r in ids])):
                if gd and any(gd):
                    m.am_grant_delay[r] = int.from_bytes(gd[:32], "big")
            roles |= new
            frontier = new
        return roles

    def check_access_managers(self, candidates: list[str]) -> None:
        """For each AccessManager seen: map the managed targets' functions to roles, follow role admins,
        and test which candidate addresses hold each role and with what execution delay. An AccessManager
        does not enumerate members; --roles-from-logs replays its RoleGranted/RoleRevoked logs instead."""
        for m in [n for n in self.seen.values() if n.kind == "access-manager"]:
            roles = self._am_map(m)
            tested: set[str] = {m.address}
            cands = set(candidates) | set(self.seen)
            for _ in range(3):   # holders found in one pass can lead to more: a Safe's signers often hold roles too
                for n in list(self.seen.values()):
                    if n.kind == "safe":
                        cands |= set(n.safe_owners)
                cands -= tested
                if not cands:
                    break
                pairs = [(r, c) for r in sorted(roles) for c in sorted(cands)]
                tested |= cands
                cands = set()
                for (r, c), res in zip(pairs, self._am_has_role(m.address, pairs)):
                    if res and res[0] and all(h != c for h, _ in m.am_roles.get(r, [])):
                        m.am_roles.setdefault(r, []).append((c, res[1]))
                        holder = self.seen.get(c) or self.probe(c)
                        if holder.kind == "safe":
                            cands |= set(holder.safe_owners)
            self._am_findings(m)

    def _am_findings(self, m: Node) -> None:
        administers: dict[int, list[int]] = {}
        for r, a in m.am_role_admin.items():
            if a == AM_PUBLIC_ROLE:
                note = f"role {r} has PUBLIC_ROLE as its admin: anyone can grant it to themselves"
                if note not in m.notes:
                    m.notes.append(note)
            elif a != r:
                administers.setdefault(a, []).append(r)
        targets = self._am_targets(m)
        for label in m.am_open:
            note = f"{label} is open to PUBLIC_ROLE: anyone can call it"
            if note not in m.notes:
                m.notes.append(note)
            for t in targets:
                if label.endswith(t.address) and f"AccessManager {m.address}: {note}" not in t.notes:
                    t.notes.append(f"AccessManager {m.address}: {note}")
        for address in m.am_unmapped:
            if m.address not in self.replayed:
                note = (f"{address} has no verified ABI, so only {len(AM_FALLBACK_FNS)} common functions were checked for the role "
                        "guarding them: rerun with --roles-from-logs")
                if note not in m.notes:
                    m.notes.append(note)
        grant_delay = lambda x: f" after {_dur(m.am_grant_delay[x])}" if m.am_grant_delay.get(x) else ""
        gates_on = lambda x, t: any(g.endswith(t.address) for g in m.am_gates.get(x, []))
        for r, holders in sorted(m.am_roles.items()):
            powers = []
            if r == 0:
                waits = [f"role {x}{grant_delay(x)}" for x in sorted(m.am_grant_delay) if m.am_grant_delay[x]]
                guard_waits = [f"{_dur(d)} on {t}" for t, d in sorted(m.am_target_delay.items())]
                powers.append("ADMIN_ROLE: can grant any role" + (f" ({', '.join(waits)})" if waits else "")
                              + " and change which role guards any function" + (f" (waits {', '.join(guard_waits)})" if guard_waits else ""))
            if administers.get(r):
                def _role(x: int) -> str:
                    fns = sorted({g.split(" on ")[0] for g in m.am_gates.get(x, [])})
                    return str(x) + (f" (calls {', '.join(fns[:3])})" if fns else "") + grant_delay(x)
                powers.append("can grant itself or others roles " + ", ".join(_role(x) for x in sorted(administers[r])))
            if m.am_gates.get(r):
                fns = sorted({g.split(" on ")[0] for g in m.am_gates[r]})
                powers.append("calls " + ", ".join(fns[:5]) + (f" and {len(fns) - 5} more" if len(fns) > 5 else ""))
            mapped = bool(powers)
            if not powers:
                powers.append("what it guards could not be mapped from the functions checked")
            for who, delay in holders:
                if delay >= LONG_DELAY:
                    continue
                c = self.seen.get(who) or self.probe(who)
                if c.kind == "eoa":
                    holder = f"EOA {who}"
                elif c.kind == "safe" and c.safe_threshold == 1:
                    holder = f"1-of-N Safe {who}"
                elif c.kind == "safe" and r == 0:
                    holder = f"{c.safe_threshold}-of-{len(c.safe_owners)} Safe {who}"
                else:
                    continue
                wait = f"only {_dur(delay)} execution delay" if delay else "no execution delay"
                note = f"role {r} held by {holder} with {wait} ({'; '.join(powers)})"
                if note not in m.notes:
                    m.notes.append(note)
                if not mapped:
                    continue
                for t in targets:
                    tn = f"AccessManager {m.address} " + note
                    reaches = r == 0 or gates_on(r, t) or any(gates_on(x, t) for x in administers.get(r, []))
                    if reaches and tn not in t.notes:
                        t.notes.append(tn)

    def _timelocked(self, n: Node, hops: int = 4) -> bool:
        """A node acts through a timelock: it is one, or every controller it has (upgrade admin, owner(), admin())
        is, within a few hops. Aave's PoolAddressesProvider is owned by an executor that the PayloadsController owns."""
        if n.kind in ("timelock", "legacy-timelock", "aragon-app"):   # an Aragon app acts only through DAO votes
            return True
        if hops == 0 or n.kind in ("eoa", "safe"):
            return False
        ctls = {a for a in (n.proxy_admin, n.owner, n.admin, n.dao, n.emergency, *n.wards) if a and a != n.address}
        if not ctls:   # an AccessControl contract with no owner: whoever holds DEFAULT_ADMIN_ROLE controls it
            ctls = {a for a in n.roles.get("DEFAULT_ADMIN_ROLE", []) if a != n.address}
        return bool(ctls) and all(self._timelocked(self.seen.get(a) or self.probe(a), hops - 1) for a in ctls)

    # ---- prove ----
    def _code(self, addr: str | None) -> bytes:
        if not addr:
            return b""
        if addr not in self._code_cache:
            self._code_cache[addr] = bytes(self.w3.eth.get_code(addr))
        return self._code_cache[addr]

    def _present(self, n: Node, sig: str) -> bool:
        """The function's selector is in the contract's own code, its implementation's or its clone target's."""
        return _sel(sig) in self._code(n.address) + self._code(n.implementation) + self._code(n.clone_of)

    def _leaf(self, addr: str | None) -> Node | None:
        """A holder worth a proof: an EOA or a Safe already seen. A controller that is itself a contract is a path to
        walk, not a leaf, so its own owner or role findings are proven on its node, not here."""
        n = self.seen.get(addr) if addr else None
        return n if n is not None and n.kind in ("eoa", "safe") else None

    def _dummy(self, ty: str):
        """A safe dummy for a simple ABI type, or None when it cannot be guessed (tuples, arrays, fixed point)."""
        if ty == "address":
            return DUMMY_ADDR
        if ty == "bool":
            return True
        if ty == "string":
            return ""
        if ty == "bytes":
            return b""
        if re.fullmatch(r"bytes\d+", ty):
            return bytes(int(ty[5:]))
        if re.fullmatch(r"u?int\d*", ty):
            return 1
        return None

    def _attempt(self, n: Node, fn: str, role: str, holder: str, types: list, values: list) -> None:
        """Simulate fn(values) on n from holder and from a stranger, and record the finding. Proven only when the call
        succeeds from the holder and reverts from the stranger; a revert from both is gated by state, not the caller."""
        if any(v is None for v in values):
            n.proofs.append(Proof(fn, role, holder, False, "an argument could not be filled with a safe dummy"))
            return
        try:
            data = _sel(fn) + (abi_encode(types, values) if types else b"")
        except Exception as e:  # noqa: BLE001
            n.proofs.append(Proof(fn, role, holder, False, f"arguments could not be encoded ({e})"))
            return
        ok_holder = self._try_call({"from": holder, "to": n.address, "data": data}) is not None
        ok_stranger = self._try_call({"from": STRANGER, "to": n.address, "data": data}) is not None
        if ok_holder and not ok_stranger:
            n.proofs.append(Proof(fn, role, holder, True))
        elif ok_holder and ok_stranger:
            n.proofs.append(Proof(fn, role, holder, False, "it succeeds from a stranger too, so the caller is not the gate"))
        elif not ok_holder and not ok_stranger:
            n.proofs.append(Proof(fn, role, holder, False, "it reverts from the holder too: gated by state, not the caller"))
        else:
            n.proofs.append(Proof(fn, role, holder, False, "it reverts from the holder but not from a stranger"))

    def _mint_fn(self, n: Node) -> tuple[str, list] | None:
        """A mint-like function with simple arguments, present in the code, from the verified ABI of the contract or
        its implementation. web3's own ERC-4626 mint(uint256,address) is not an admin mint and is skipped."""
        from .decode import verified_abi
        abi: list = []
        try:
            chain_id = self.w3.eth.chain_id
            for a in (n.address, n.implementation, n.clone_of):
                if a:
                    abi += verified_abi(chain_id, a) or []
        except Exception:  # noqa: BLE001
            pass
        for f in abi:
            types = [_abi_type(i) for i in f.get("inputs") or []]
            sig = f"{f.get('name')}({','.join(types)})"
            if (f.get("type") == "function" and f.get("stateMutability") not in ("view", "pure")
                    and MINT_FN_NAME.search(f.get("name", "")) and sig != "mint(uint256,address)"
                    and all(SIMPLE_ARG.match(t) for t in types) and self._present(n, sig)):
                return sig, types
        return None

    def _prove_owner(self, n: Node) -> None:
        holder = self._leaf(n.owner)
        if holder is None:
            return
        for fn, types in OWNER_FNS.items():
            if self._present(n, fn):
                self._attempt(n, fn, "owner()", holder.address, types, [self._dummy(t) for t in types])
                return
        n.proofs.append(Proof("onlyOwner function", "owner()", n.owner, False,
                              "no transferOwnership/setOwner/setPeer/setDelegate in the code to simulate"))

    def _prove_upgrade(self, n: Node) -> None:
        if not (n.implementation or n.beacon):
            return
        holder = self._leaf(n.proxy_admin) or (self._leaf(n.owner) if not n.proxy_admin else None)
        if holder is None:    # the upgrade path runs through a contract; its own node carries the leaf proof
            return
        role = "upgrade admin" if holder.address == n.proxy_admin else "UUPS upgrade via owner()"
        fn = next((f for f in UPGRADE_FNS if self._present(n, f)), None)
        if fn is None:
            n.proofs.append(Proof("upgradeToAndCall/upgradeTo", role, holder.address, False,
                                  "no upgrade function found in the proxy or implementation code"))
            return
        impl = n.implementation or DUMMY_ADDR
        values = [impl, b""] if fn == "upgradeToAndCall(address,bytes)" else [impl]
        self._attempt(n, fn, role, holder.address, UPGRADE_FNS[fn], values)

    def _prove_roles(self, n: Node) -> None:
        done: set[tuple[str, str]] = set()
        for role, holders in n.roles.items():
            if role in ("PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"):
                continue   # timelock-internal: PROPOSER_ROLE is proven by _prove_proposer, the others are not simulated here
            for who in holders:
                if who == ZERO or self._leaf(who) is None:
                    continue
                attempt = None
                if re.search(r"PAUS", role) and self._present(n, "pause()"):
                    attempt = ("pause()", [], [])
                elif re.search(r"MINT|ISSU|BRIDGE", role) and (mf := self._mint_fn(n)):
                    attempt = (mf[0], mf[1], [self._dummy(t) for t in mf[1]])
                elif re.search(r"UPGRAD", role) and (uf := next((f for f in UPGRADE_FNS if self._present(n, f)), None)):
                    impl = n.implementation or DUMMY_ADDR
                    attempt = (uf, UPGRADE_FNS[uf], [impl, b""] if uf == "upgradeToAndCall(address,bytes)" else [impl])
                elif role == "DEFAULT_ADMIN_ROLE" and self._present(n, "grantRole(bytes32,address)"):
                    # DEFAULT_ADMIN_ROLE is its own admin, so the holder can grant it; a stranger cannot
                    attempt = ("grantRole(bytes32,address)", ["bytes32", "address"], [ROLES["DEFAULT_ADMIN_ROLE"], DUMMY_ADDR])
                if attempt is None:
                    if (role, who) not in done:
                        n.proofs.append(Proof(f"{role} power", role, who, False,
                                              "no function for this role found in the code (grantRole proves only DEFAULT_ADMIN_ROLE)"))
                        done.add((role, who))
                    continue
                if (attempt[0], who) in done:
                    continue
                done.add((attempt[0], who))
                self._attempt(n, attempt[0], role, who, attempt[1], attempt[2])

    def _prove_proposer(self, n: Node) -> None:
        proposers = [h for h in n.roles.get("PROPOSER_ROLE", []) if self._leaf(h)]
        if not proposers:
            return
        if not self._present(n, SCHEDULE_FN):
            for h in proposers:
                n.proofs.append(Proof(SCHEDULE_FN, "PROPOSER_ROLE", h, False,
                                      "this timelock has no OpenZeppelin schedule(...); a legacy queueTransaction needs a future eta"))
            return
        delay = self._uint(n.address, "getMinDelay()")
        if delay is None:
            for h in proposers:
                n.proofs.append(Proof(SCHEDULE_FN, "PROPOSER_ROLE", h, False, "getMinDelay() did not answer, so the schedule delay is unknown"))
            return
        types = ["address", "uint256", "bytes", "bytes32", "bytes32", "uint256"]
        values = [DUMMY_ADDR, 0, b"", bytes(32), DUMMY_SALT, delay]
        for h in proposers:
            self._attempt(n, SCHEDULE_FN, "PROPOSER_ROLE", h, types, values)

    def prove(self) -> None:
        """Back every finding with a simulation. For each owner, upgrade admin, role holder or timelock proposer that is
        an EOA or a Safe, run its privileged call as an eth_call from the holder (expect success) and from a stranger
        (expect revert). eth_call only; nothing is sent. Every simulation reads one block, pinned here so the holder's
        call and the stranger's see the same state. A finding is proven only when the call succeeds from the holder and
        reverts from the stranger; anything else is reported, never claimed proven."""
        if self.w3.eth.default_block in (None, "latest"):
            self.w3.eth.default_block = self.w3.eth.block_number      # one block for every simulation, as the rest of the probe read
        for n in [x for x in self.seen.values() if x.kind != "eoa"]:
            n.proofs = []
            if n.owner and n.owner != n.address:
                self._prove_owner(n)
            self._prove_upgrade(n)
            self._prove_roles(n)
            if n.kind == "timelock":
                self._prove_proposer(n)

    # ---- probe ----
    def _has_timelock_functions(self, address: str, code: bytes, implementation: str | None) -> bool:
        """Whether a contract with a delay getter can actually queue things: known timelock selectors in its code
        or its implementation's, or queue/schedule/propose functions in its verified ABI."""
        from .decode import verified_abi
        codes = code + (bytes(self.w3.eth.get_code(implementation)) if implementation else b"")
        if any(_sel(f) in codes for f in TIMELOCK_FNS):
            return True
        try:
            chain_id = self.w3.eth.chain_id
            abi = [f for a in (address, implementation) if a for f in verified_abi(chain_id, a) or []]
        except Exception:  # noqa: BLE001
            abi = []
        return any(f.get("type") == "function" and TIMELOCK_FN_NAME.search(f.get("name", "")) for f in abi)

    def _safe_modules(self, address: str) -> list[str]:
        r = self._call_args(address, "getModulesPaginated(address,uint256)", _pad("0x" + "00" * 19 + "01") + (50).to_bytes(32, "big"))
        if not r:
            return []
        try:
            modules, _next = abi_decode(["address[]", "address"], r)
        except Exception:  # noqa: BLE001
            return []
        return [Web3.to_checksum_address(m) for m in modules]

    def probe(self, address: str) -> Node:
        address = Web3.to_checksum_address(address)
        if address in self.seen:
            return self.seen[address]
        n = Node(address=address)
        self.seen[address] = n
        code = bytes(self.w3.eth.get_code(address))
        n.code_size = len(code)
        if n.code_size == 23 and code[:3] == EIP7702_PREFIX:
            n.kind = "eoa"     # an EOA with an EIP-7702 delegation: the private key still controls it
            n.delegate = Web3.to_checksum_address("0x" + code[3:].hex())
            return n
        if n.code_size == 0:
            n.kind = "eoa"
            return n
        n.clone_of = _clone_target(code)
        n.implementation = self._slots_addr(address, IMPL_SLOT, *LEGACY_IMPL_SLOTS)
        n.proxy_admin = self._slots_addr(address, ADMIN_SLOT, LEGACY_ADMIN_SLOT)
        n.beacon = self._slot_addr(address, BEACON_SLOT)
        if n.clone_of and not n.beacon:
            n.beacon = self._slot_addr(n.clone_of, BEACON_SLOT)   # a clone runs its target's code, so the target's beacon can swap it
        if n.implementation and not n.proxy_admin and not n.beacon:
            n.proxy_admin, n.admin_factory = self._factory_admin(address, code)
            if not n.proxy_admin:
                n.proxy_admin = self._immutable_admin(address, code)
        if n.beacon:
            b = self.probe(n.beacon)     # whoever can change the beacon's implementation upgrades this proxy
            n.proxy_admin = n.proxy_admin or b.owner or b.proxy_admin or b.admin
            n.implementation = n.implementation or self._addr(n.beacon, "implementation()")
        thr = self._uint(address, "getThreshold()")
        owners = self._call(address, "getOwners()")
        # a catch-all fallback answers both of these with junk, so the array has to add up
        count = int.from_bytes(owners[32:64], "big") if owners and len(owners) >= 64 else 0
        if thr is not None and 0 < count <= (len(owners) - 64) // 32 and int.from_bytes(owners[:32], "big") == 32:
            n.kind = "safe"
            n.safe_threshold = thr
            n.safe_owners = [Web3.to_checksum_address("0x" + owners[64 + 32 * i + 12: 64 + 32 * i + 32].hex())
                             for i in range(count)]
            n.safe_modules = self._safe_modules(address)
            if thr == 1:
                n.notes.append("1-of-N Safe: a single owner can act")
            elif thr * 2 < count:
                n.notes.append(f"{thr}-of-{count} Safe: fewer than half the owners are needed")
            elif thr * 2 == count:
                n.notes.append(f"{thr}-of-{count} Safe: half the owners are enough")
        d = self._uint(address, "getMinDelay()")      # OpenZeppelin TimelockController
        if d is None:
            for getter in ("getDelay()", "minDelay()"):     # Aave executors and similar; Solady Timelock
                if d is None and n.kind == "unknown":
                    v = self._uint(address, getter)
                    if v is not None and self._has_timelock_functions(address, code, n.implementation):
                        d = v
        if d is None:
            d = self._executor_delay(address)         # Aave Governance V3 PayloadsController
        if d is not None and n.kind == "unknown":
            n.kind = "timelock"
            n.delay = d
        legacy = self._uint(address, "delay()")
        legacy_admin = self._addr(address, "admin()")
        if (legacy is not None and n.kind == "unknown" and not legacy_admin and self._addr(address, "authority()")
                and self._call_args(address, "plans(bytes32)", bytes(32)) is not None):
            n.kind = "timelock"                   # Sky/Maker DSPause: delay() + authority() (the chief), plans
            n.delay = legacy
        if legacy is not None and legacy_admin and n.kind == "unknown" and self._has_timelock_functions(address, code, n.implementation):
            n.kind = "legacy-timelock"            # Compound-style: delay() + admin()
            n.delay = legacy
            n.admin = legacy_admin
        elif (legacy is not None and n.kind == "unknown" and not n.implementation and not n.beacon
              and 3600 <= legacy <= 90 * 86400 and self._addr(address, "owner()")
              and self._has_timelock_functions(address, code, None)):
            n.kind = "timelock"                   # custom Ownable timelock: delay() + owner()
            n.delay = legacy
        if n.kind == "unknown" and self._is_access_manager(address):
            n.kind = "access-manager"
        if n.kind == "unknown":
            n.kind = "proxy" if (n.implementation or n.beacon) else "contract"
        if n.kind in ("proxy", "contract"):
            auth_ = self._addr(address, "authority()")
            if auth_ and auth_ != address and self._is_access_manager(auth_):
                n.authority = auth_
        n.owner = self._addr(address, "owner()")
        n.pending_owner = self._addr(address, "pendingOwner()")
        if self._call(address, "appId()") is not None:
            n.kernel = self._addr(address, "kernel()")
        if n.kernel and n.kind in ("contract", "proxy"):
            n.kind = "aragon-app"
            n.notes.append(f"Aragon app: upgrades and permissions are granted in the ACL of kernel {n.kernel} "
                           "(APP_MANAGER_ROLE and app roles), normally only through DAO votes; ACL holders are not listed here")
        auth = self._addr(address, "getAuthorizer()")
        if auth:
            n.authorizer = self._addr(auth, "getActualAuthorizer()") or auth
        n.dao = self._addr(address, "dao()")
        n.emergency = self._addr(address, "emergency()")
        upgrade_admin = self._addr(address, "upgradeAdmin()")   # Euler-style factories upgrade their beacon proxies
        if upgrade_admin and not n.proxy_admin:
            n.proxy_admin = upgrade_admin
        if n.kind not in ("eoa", "safe") and self._call_args(address, "wards(address)", bytes(32)) is not None:
            r = self._call_args(address, "wards(address)", bytes(12) + bytes.fromhex(SKY_PAUSE_PROXY[2:]))
            if r and int.from_bytes(r[:32], "big") == 1:
                n.wards.append(SKY_PAUSE_PROXY)
        if n.admin is None:
            n.admin = n.proxy_admin or self._addr(address, "admin()") if n.kind != "safe" else None
            if n.admin is None and n.kind != "safe":
                n.admin = self._addr(address, "getAdmin()")
                if n.admin:
                    n.admin_getter = "getAdmin()"
        p = self._call(address, "paused()")
        if p is not None and len(p) == 32:
            n.paused = bool(int.from_bytes(p, "big"))
        if n.kind in ("timelock", "legacy-timelock") and n.delay is not None:
            if n.delay == 0:
                n.notes.append("timelock delay is 0")
            elif n.delay < 86400:
                n.notes.append(f"timelock delay is only {_dur(n.delay)}")
        # follow the controllers all the way up: a key three hops above a proxy is still the key that upgrades it
        if len(self.seen) >= MAX_NODES:
            if "controller walk stopped" not in " ".join(self.incomplete):
                self.incomplete.append(f"controller walk stopped at {MAX_NODES} addresses: this graph is not fully covered")
        else:
            links: dict[str, list[str]] = {}
            if n.proxy_admin and n.proxy_admin != address:
                links.setdefault(n.proxy_admin, []).append("upgrade admin")
            if n.owner and n.owner != address:
                links.setdefault(n.owner, []).append("owner()")
            if n.admin and n.admin != address and n.admin != n.proxy_admin:
                links.setdefault(n.admin, []).append(n.admin_getter)
            for ctl, what in ((n.authorizer, "authorizer"), (n.dao, "dao()"), (n.emergency, "emergency()"), *((w, "ward") for w in n.wards)):
                if ctl and ctl != address:
                    links.setdefault(ctl, []).append(what)
            if n.beacon and not n.proxy_admin:
                links.setdefault(n.beacon, []).append("upgrade beacon")
            if n.authority:
                self.probe(n.authority)   # its role holders are resolved in check_roles
            for module in n.safe_modules:
                c = self.probe(module)
                cooldown = self._uint(module, "txCooldown()") if c.kind != "eoa" else None
                if cooldown is not None and self._call(module, "queueNonce()") is not None:
                    # Zodiac Delay modifier: its own modules queue, anyone executes after the cooldown. A recovery path, not a bypass.
                    queuers = self._safe_modules(module)
                    for q in queuers:
                        self.probe(q)
                    n.notes.append(f"Safe module {module} is a Zodiac Delay modifier: transactions queued by "
                                   f"{', '.join(queuers) or 'its modules (none enabled)'} execute without the signers after a {_dur(cooldown)} cooldown")
                else:
                    n.notes.append(f"Safe module {module} ({'an EOA' if c.kind == 'eoa' else c.kind}) can execute without the signers")
            for ctl, roles in links.items():
                c = self.probe(ctl)
                what = " and ".join(roles)
                if c.kind == "eoa":
                    n.notes.append(f"{what} is an EOA {ctl}" + (f" (EIP-7702 delegated to {c.delegate})" if c.delegate else "")
                                   + (": no multisig on-chain" if n.kind in ("timelock", "legacy-timelock")
                                      else ": no timelock or multisig on-chain"))
                elif c.kind == "safe" and c.safe_threshold == 1:
                    n.notes.append(f"{what} is a 1-of-N Safe {ctl}")
                elif c.kind in ("safe", "contract", "proxy") and n.kind in ("proxy", "contract") and not self._timelocked(c):
                    if roles == ["owner()"] and n.proxy_admin and n.proxy_admin != ctl:
                        n.notes.append(f"owner() is {ctl} with no timelock: owner-level settings change immediately "
                                       f"(upgrades are separate, via {n.proxy_admin})")
                    else:
                        n.notes.append(f"{what} is {ctl} with no recognised timelock in between")
            if n.kind in ("proxy", "contract"):
                for sig, label in NAMED_GETTERS.items():
                    a = self._addr(address, sig)
                    if not a or a == address or a in (n.owner, n.proxy_admin, n.admin):
                        continue
                    if sig == "safe()" and self._call(address, "totalAssets()") is None:
                        label = "safe()"    # plenty of modules name their Safe; only a vault's holds its assets
                    n.named[label] = a
                    c = self.probe(a)
                    if c.kind == "eoa":
                        n.notes.append(f"{label} is an EOA {a}" + (f" (EIP-7702 delegated to {c.delegate})" if c.delegate else ""))
                    elif c.kind == "safe" and c.safe_threshold == 1:
                        n.notes.append(f"{label} is a 1-of-N Safe {a}")
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
    for label, v in (("kernel", n.kernel), ("authorizer", n.authorizer), ("dao", n.dao), ("emergency", n.emergency)):
        if v:
            bits.append(f"{label}={v}")
    if n.wards:
        bits.append(f"wards={','.join(n.wards)}")
    if n.clone_of:
        bits.append(f"clone_of={n.clone_of}")
    if n.authority:
        bits.append(f"authority={n.authority}")
    if n.delegate:
        bits.append(f"7702-delegate={n.delegate}")
    for label, a in n.named.items():
        bits.append(f"{label.split(' ')[0]}={a}")
    if n.safe_threshold is not None:
        bits.append(f"safe {n.safe_threshold}-of-{len(n.safe_owners)}")
    if n.safe_modules:
        bits.append(f"modules={','.join(n.safe_modules)}")
    if n.delay is not None:
        bits.append(f"delay={n.delay}s")
    if n.paused is not None:
        bits.append(f"paused={n.paused}")
    if n.open_executor is not None:
        bits.append(f"openExecutor={n.open_executor}")
    s = "  ".join(bits)
    for role, holders in n.roles.items():
        s += f"\n    {role}: {', '.join(holders)}"
    for r, holders in sorted(n.am_roles.items()):
        s += f"\n    role {r}: " + ", ".join(f"{h} (delay {d}s)" for h, d in holders)
        if r in n.am_role_admin and n.am_role_admin[r] != r:
            s += f" [admin role {n.am_role_admin[r]}]"
    for note in n.notes:
        s += f"\n    ! {note}"
    for p in n.proofs:
        s += f"\n    {p.line()}"
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


CHAIN_NAMES = {1: "ethereum", 10: "optimism", 56: "bsc", 100: "gnosis", 137: "polygon", 8453: "base",
               42161: "arbitrum", 43114: "avalanche", 59144: "linea", 534352: "scroll"}


def chain_name_for(chain_id: int) -> str:
    return CHAIN_NAMES.get(chain_id, f"chain {chain_id}")


def fact_lines(prober: Prober, chain_name: str) -> list[str]:
    """Every control fact in the report, one per line with full addresses, sorted. The ownerwatch Action compares
    these lines, so a change to anything here is drift; only what the tool sees of the chain goes in, no prose."""
    out = []
    for n in prober.seen.values():
        pairs: list[tuple[str, object]] = [("kind", n.kind)]
        pairs += [(k, v) for k, v in (("implementation", n.implementation), ("upgrade_admin", n.proxy_admin), ("beacon", n.beacon),
                                      ("owner", n.owner), ("pending_owner", n.pending_owner), ("admin", n.admin), ("clone_of", n.clone_of),
                                      ("authority", n.authority), ("kernel", n.kernel), ("authorizer", n.authorizer), ("dao", n.dao),
                                      ("emergency", n.emergency), ("delegate", n.delegate), ("threshold", n.safe_threshold),
                                      ("delay", n.delay)) if v is not None]
        pairs += [("signer", a) for a in n.safe_owners] + [("module", a) for a in n.safe_modules] + [("ward", a) for a in n.wards]
        if n.paused:
            pairs.append(("paused", "true"))
        if n.open_executor:
            pairs.append(("open_executor", "true"))
        pairs += [(label.split(" ")[0], a) for label, a in n.named.items()]
        pairs += [(f"role {role}", h) for role, holders in n.roles.items() for h in holders]
        pairs += [(f"am_role {r}", f"{h} delay {d}") for r, holders in n.am_roles.items() for h, d in holders]
        pairs += [(f"am_role_admin {r}", a) for r, a in n.am_role_admin.items() if a]
        pairs += [(f"am_gate {r}", g) for r, gates in n.am_gates.items() for g in gates]
        out += [f"{chain_name} {n.address} {k} {v}" for k, v in pairs]
    return sorted(out)


def markdown_report(prober: Prober, label: str, chain_name: str, roots: list[Node], prove: bool = False) -> str:
    """A short admin-surface report a protocol team can read in two minutes. With prove=True (the probe's --prove) a
    Proofs section shows each finding backed by a simulation, or why it could not be."""
    def short(a: str) -> str:
        return a[:6] + "…" + a[-4:]

    lines = [f"# {label} admin surface on {chain_name}", ""]
    lines += ["| Address | Type | Controlled by | Detail |", "|---|---|---|---|"]
    for n in prober.seen.values():
        if n.kind == "eoa":
            continue
        ctl = n.proxy_admin or n.owner or n.admin or n.authority or "-"
        detail = []
        if n.safe_threshold is not None:
            detail.append(f"{n.safe_threshold}-of-{len(n.safe_owners)}")
        if n.safe_modules:
            detail.append("modules: " + ", ".join(short(a) for a in n.safe_modules))
        if n.delay is not None:
            detail.append(f"{_dur(n.delay)} delay")
        if n.implementation:
            detail.append(f"impl {short(n.implementation)}")
        if n.beacon:
            detail.append(f"beacon {short(n.beacon)}")
        if n.clone_of:
            detail.append(f"EIP-1167 clone of {short(n.clone_of)} ({'upgradeable through its beacon' if n.beacon else 'not upgradeable'})")
        if n.owner and n.owner != ctl:
            detail.append(f"owner {short(n.owner)}")
        if n.pending_owner:
            detail.append(f"pending owner {short(n.pending_owner)}")
        if n.authority:
            detail.append(f"AccessManager {short(n.authority)}")
        for label, a in n.named.items():
            detail.append(f"{label.split(' ')[0]}: {short(a)}")
        for r, holders in sorted(n.am_roles.items()):
            name = "ADMIN_ROLE (0)" if r == 0 else f"role {r}"
            detail.append(f"{name}: " + ", ".join(f"{short(h)}" + (f" ({d}s delay)" if d else "") for h, d in holders))
        if n.open_executor:
            detail.append("open executor")
        if n.paused:
            detail.append("PAUSED")
        for role, holders in n.roles.items():
            detail.append(f"{role}: " + ", ".join(short(h) for h in holders))
        lines.append(f"| `{short(n.address)}` | {n.kind} | `{short(ctl) if ctl != '-' else '-'}` | {'; '.join(detail) or '-'} |")
    # the manager's own row states each AccessManager finding; repeating it per target buries the rest of the report
    risks = [(n.address, note) for n in prober.seen.values() for note in n.notes if not note.startswith("AccessManager 0x")]
    lines += ["", "## Findings", ""]
    if risks:
        for a, note in risks:
            lines.append(f"- `{short(a)}`: {note}")
        if any("EOA" in note for _, note in risks):
            lines.append("- The chain shows an address, not how its key is held: an EOA above may be one key or an MPC wallet.")
    else:
        lines.append("- No single-key or zero-delay control paths found among the probed addresses.")
    if any(n.kind == "access-manager" and n.address not in prober.replayed for n in prober.seen.values()):
        lines.append("- An AccessManager was found. It does not list its members, so only the tested addresses were checked for "
                     "roles: rerun with --roles-from-logs, or pass likely holders with --role-candidates.")
    lines += [f"- Not covered: {x}" for x in prober.incomplete]
    if prove:
        proofs = [(n.address, p) for n in prober.seen.values() for p in n.proofs]
        lines += ["", "## Proofs", "",
                  "Each privileged call run as an `eth_call` at the pinned block: it must succeed from the holder and "
                  "revert from a stranger (`0x…dEaD`) to count as proof. Nothing was sent on-chain. A call that reverts "
                  "from both is gated by state, not the caller, and proves nothing.", ""]
        if proofs:
            lines += [f"- `{short(a)}`: {p.line(short)}" for a, p in proofs]
        else:
            lines.append("- Nothing to simulate: no owner, upgrade admin, role holder or proposer that is an EOA or a Safe was found.")
    chain_summary = []
    for r in roots:
        path, cur, hops = [r], r, 0
        while hops < 3:
            nxt = cur.proxy_admin or cur.owner or cur.admin or cur.authority
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
              "## Full facts", "", "The ownerwatch Action compares these lines to catch drift. Nothing here is shortened.", "",
              "```ownerwatch-facts", *fact_lines(prober, chain_name), "```", "",
              f"_Generated by `ownerwatch probe` {__version__} on {chain_name}. Read-only; nothing was sent on-chain._"]
    return "\n".join(lines) + "\n"
