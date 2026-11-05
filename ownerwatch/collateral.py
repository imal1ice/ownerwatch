"""Curator collateral report: who can mint, upgrade or pause the tokens a Morpho vault lends against.

A MetaMorpho vault (V1) lists its Morpho Blue markets in withdrawQueue and supplyQueue. A Morpho Vault V2 reaches them
through adapters: a market adapter holds Morpho Blue positions itself, a vault adapter holds shares of another vault.
Either way the depositors' money ends up in markets, each with one collateral token and one oracle. This module finds
those markets from chain state alone, works out what the vault has in each, probes every collateral token (and what it
wraps) and every oracle, and writes a report ranked by allocation, plus a config that watches all of it.

Every read is at one pinned block. A read that fails is reported as failed, never as an empty answer: "no owner found"
and "the owner could not be read" must not look the same.
"""
from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

import requests
import yaml
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from web3 import Web3
from web3.exceptions import Web3Exception

from . import __version__
from .alerts import redact
from .probe import ROLES, ZERO, Node, ProbeRpcError, Prober, _dur, _pad, _sel, _word_addr, chain_name_for
from .safe import SafeQueueWatcher

PIN_BEHIND = 5          # blocks behind the head: the nodes behind a load-balanced public RPC are not all at the tip
MAX_NESTING = 3         # vaults inside vaults: a V2 adapter that holds shares of another vault
RECONCILE_BPS = 50      # Morpho stores market totals as of the last accrual, so markets plus idle trail totalAssets() a little
VIRTUAL_SHARES, VIRTUAL_ASSETS = 10**6, 1        # Morpho Blue SharesMathLib
# No code, no balance, no role anywhere: a call that passes from this address is open to everyone
STRANGER = Web3.to_checksum_address("0x" + bytes(Web3.keccak(text="ownerwatch stranger"))[-20:].hex())
READ_ERRORS = (RuntimeError, ValueError, OSError, requests.RequestException, Web3Exception)
# The state at the pinned block is gone (a non-archive RPC moved on): retrying will not bring it back
GONE = ("archive", "missing trie node", "header not found", "pruned", "state not available", "state histories")
# A wrapper is only as safe as what it wraps: Pendle PT SY() and SY yieldToken() (an SY also answers asset() with the
# token under its yield token), wstETH stETH(), ERC-4626 asset()
UNDERLYING_GETTERS = ("SY()", "yieldToken()", "stETH()", "asset()", "underlying()", "UNDERLYING_ASSET_ADDRESS()")
MINT_GETTERS = ("minter()", "getMinter()", "masterMinter()", "MINTER()", "minterAddress()", "bridge()", "l2Bridge()", "BRIDGE()")
GETTER_LABEL = {"masterMinter()": "masterMinter() (adds minters and sets their allowances)", "bridge()": "bridge() (mints bridged supply)",
                "l2Bridge()": "l2Bridge() (mints bridged supply)", "BRIDGE()": "BRIDGE() (mints bridged supply)"}
# Per-address minter lists (FiatToken isMinter, Maker-style minters), tested for every address in the report
MINTER_CHECKS = ("isMinter(address)", "minters(address)")
PAUSE_GETTERS = ("pauser()", "pauseGuardian()")
# Tokens that keep their roles in a separate AccessControl contract (Midas, Usual and others)
ACL_GETTERS = ("accessControl()", "registryAccess()")
# Simulated with eth_call at the pinned block from every address that controls the token. A success shows that the
# address can make the call; a revert shows nothing (a cap or a minimum can stop a real minter), so only successes count.
MINT_FNS = {"mint(address,uint256)": ["address", "uint256"], "mintTo(address,uint256)": ["address", "uint256"],
            "mint(uint256)": ["uint256"], "mint(uint256,address)": ["uint256", "address"], "issue(uint256)": ["uint256"],
            "bridgeMint(address,uint256)": ["address", "uint256"], "crosschainMint(address,uint256)": ["address", "uint256"]}
PAUSE_FNS = {"pause()": []}
# More of them by name from the verified ABI, when every argument is a plain value a simulation can fill in
ABI_FN = {"mint": re.compile(r"^(mint|issue)", re.I), "pause": re.compile(r"^(pause|freeze)", re.I)}
SIMPLE_ARG = re.compile(r"^(address|bool|string|bytes\d*|u?int\d*)$")
NOT_ADMIN_MINT = {"mint(uint256,address)", "mintByYT(address,uint256)"}   # ERC-4626 share mint, Pendle PT mint by its YT
OWNER_GETTERS = ("governor()",)
# Contracts that often hold a token's mint or pause power without a getter that says so. Simulated from, never reported
# unless a simulation passes.
SIM_GETTERS = ("vault()", "vaultAddress()", "manager()", "controller()", "pool()")     # Origin and others gate their admin functions and upgrades on governor()
UUPS_FNS = ("upgradeToAndCall(address,bytes)", "upgradeTo(address)")
MINT_ROLE = re.compile(r"MINT|ISSU|BRIDGE", re.I)
PAUSE_ROLE = re.compile(r"PAUS", re.I)
EXTRA_ROLES = {k: bytes(Web3.keccak(text=k)) for k in ("MINT_ROLE", "MINTER", "BRIDGE_ROLE", "ISSUER_ROLE", "PAUSE_ROLE", "PAUSER")}
FEEDS = ("BASE_FEED_1()", "BASE_FEED_2()", "QUOTE_FEED_1()", "QUOTE_FEED_2()", "BASE_VAULT()", "QUOTE_VAULT()")
# Explorers with an Etherscan-style logs API and no key. Plain AccessControl does not list role members and free RPCs
# keep little log history, so the RoleGranted index there supplies the accounts to test. Hints only: an account counts
# as a holder when hasRole() says so at the pinned block, so a stale or partial index cannot add a holder.
EXPLORERS = {1: ["https://eth.blockscout.com/api", "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"],
             10: ["https://optimism.blockscout.com/api"], 100: ["https://gnosis.blockscout.com/api"], 137: ["https://polygon.blockscout.com/api"],
             8453: ["https://base.blockscout.com/api"], 42161: ["https://arbitrum.blockscout.com/api"]}
ROLE_GRANTED = "0x" + bytes(Web3.keccak(text="RoleGranted(bytes32,address,address)")).hex()
KIND_LABEL = {"safe": "Safe", "timelock": "Timelock", "legacy-timelock": "Timelock", "proxy": "Proxy", "access-manager": "AccessManager"}


class NotAVault(ValueError):
    """The address answers neither as a MetaMorpho V1 vault nor as a Morpho Vault V2."""


def _retry(fn, log=None, tries: int = 4):
    """fn(), retried through rate limits and dropped connections. Reverts and missing state are not retried."""
    for attempt in range(tries):
        try:
            return fn()
        except NotAVault:
            raise
        except READ_ERRORS as e:
            msg = redact(e).lower()
            if attempt == tries - 1 or any(g in msg for g in GONE) or "revert" in msg:
                raise
            wait = 5 * (attempt + 1) if ("429" in msg or "too many" in msg or "rate" in msg) else 2 * (attempt + 1)
            if log:
                log(f"  read failed ({redact(e)}); retrying in {wait}s")
            time.sleep(wait)


def _a(word: bytes) -> str:
    return Web3.to_checksum_address("0x" + word[12:32].hex())


def _u(word: bytes, i: int = 0) -> int:
    return int.from_bytes(word[32 * i:32 * i + 32], "big")


def _text(raw: bytes | None) -> str | None:
    """A string return value, or a bytes32 one (MKR and other early tokens)."""
    if not raw:
        return None
    try:
        return abi_decode(["string"], raw)[0]
    except Exception:  # noqa: BLE001
        return raw[:32].rstrip(b"\x00").decode("utf-8", "replace") or None


def amount(raw: int, decimals: int | None) -> str:
    if decimals is None:
        return f"{raw:,} (raw units: decimals() did not answer)"
    return f"{Decimal(raw).scaleb(-decimals):,.2f}"


def _pct(part: int, whole: int) -> str:
    return f"{part * 100 / whole:.1f}%" if whole else "-"


@dataclass
class Market:
    id: str
    loan: str
    collateral: str
    oracle: str
    irm: str
    lltv: int
    assets: int = 0            # the vault's supply, in loan-token units, at the market's last accrual
    cap: int | None = None     # MetaMorpho V1 supply cap; Vault V2 caps are kept per id on the vault and not read here
    via: list[str] = field(default_factory=list)    # vault and adapter addresses the money passes through


@dataclass
class Token:
    address: str
    symbol: str = "?"
    name: str = ""
    decimals: int | None = None
    assets: int = 0
    markets: list[Market] = field(default_factory=list)
    error: str | None = None        # the probe failed: nothing about this token's control can be stated
    erc4626: bool = False
    registry: str | None = None     # a separate AccessControl contract that holds the token's roles
    getters: dict[str, str] = field(default_factory=dict)      # minter(), pauser() ... -> address
    role_scope: dict[str, str] = field(default_factory=dict)   # role name -> how its holders were found
    powers: dict[str, tuple[str, list[str]]] = field(default_factory=dict)   # owner/upgrade/mint/pause -> (cell, detail lines)
    findings: list[str] = field(default_factory=list)
    open: list[str] = field(default_factory=list)      # what this report could not establish about the token
    sim_extra: list[str] = field(default_factory=list)     # from SIM_GETTERS: callers worth simulating from
    wraps: Token | None = None
    wraps_ranked: str | None = None      # the token it wraps is itself collateral in this vault, with its own section
    pendle_yt: str | None = None         # a Pendle PT: its YT mints it against SY deposits
    parent: str | None = None


class CollateralReport:
    def __init__(self, w3: Web3, vault: str, block: int | None = None, log=None, roles_from_logs: bool = False, logs_w3: Web3 | None = None):
        self.w3 = w3
        self.vault = Web3.to_checksum_address(vault)
        self.log = log or (lambda m: None)
        head = _retry(lambda: w3.eth.block_number, self.log)
        self.block = block if block is not None else max(head - PIN_BEHIND, 0)
        if self.block > head:
            raise ValueError(f"block {self.block} is ahead of the RPC's head {head}")
        w3.eth.default_block = self.block          # every read below is at this one block
        self.timestamp = int(_retry(lambda: w3.eth.get_block(self.block), self.log)["timestamp"])
        self.chain_id = _retry(lambda: w3.eth.chain_id, self.log)
        self.chain = chain_name_for(self.chain_id)
        self.prober = Prober(w3)
        self.roles_from_logs, self.logs_w3 = roles_from_logs, logs_w3
        self.markets: dict[str, Market] = {}
        self.tokens: list[Token] = []
        self.oracles: dict[str, dict] = {}
        self.uncovered: list[str] = []      # parts of the vault's money this report does not map to markets
        self.failed: list[str] = []         # reads that failed after retries
        self.unmapped_assets = 0
        self.roles_error: str | None = None
        self._code: dict[str, bytes] = {}
        self._frozen = False                # set once the reads are done: writing the report must not read the chain
        self._governor: dict[str, bool] = {}
        self.oracle_lines: dict[str, tuple[str, list[str]]] = {}
        self.vault_role_lines: dict[str, str] = {}
        self.hinted: set[str] = set()       # contracts whose role holders were taken from the explorer's RoleGranted index
        self.enumerable: set[str] = set()   # AccessControl contracts that list their members: every holder is known
        self.explorer_error: str | None = None
        self._explorers = list(EXPLORERS.get(self.chain_id, []))    # the ones still answering, best first
        self.explorers_used: set[str] = set()
        self.explorers_dropped: list[str] = []

    # ---- reads ----
    def _must(self, calls: list[tuple[str, bytes]], what: str) -> list[bytes]:
        """Batched reads that must all answer: a market, a queue entry, a balance. A missing answer is a failed read."""
        res = self.prober._batch_calls(calls) if calls else []
        if any(r is None for r in res):
            raise ProbeRpcError(f"{what}: no answer at block {self.block}")
        return res

    def _uint(self, addr: str, sig: str, args: bytes = b"") -> int | None:
        r = self.prober._call_args(addr, sig, args) if args else self.prober._call(addr, sig)
        return _u(r) if r and len(r) >= 32 else None

    def _must_uint(self, addr: str, sig: str, args: bytes = b"") -> int:
        v = self._uint(addr, sig, args)
        if v is None:
            raise ProbeRpcError(f"{sig} on {addr}: no answer at block {self.block}")
        return v

    def code(self, addr: str | None) -> bytes:
        if not addr:
            return b""
        if addr not in self._code:
            self._code[addr] = bytes(self.w3.eth.get_code(addr))
        return self._code[addr]

    def version(self, addr: str) -> str:
        if self._uint(addr, "withdrawQueueLength()") is not None and self.prober._addr(addr, "MORPHO()"):
            return "MetaMorpho V1.1" if self.prober._call(addr, "lostAssets()") is not None else "MetaMorpho V1.0"
        if self._uint(addr, "adaptersLength()") is not None and self.prober._addr(addr, "asset()"):
            return "Morpho Vault V2"
        why = "it has no code" if not self.code(addr) else \
            "neither MORPHO() with withdrawQueueLength() (MetaMorpho V1) nor adaptersLength() (Morpho Vault V2) answers"
        raise NotAVault(f"{addr} is not a Morpho vault at block {self.block}: {why}")

    def read_vault(self, addr: str, num: int = 1, den: int = 1, via: list[str] | None = None) -> None:
        """Add the markets behind a vault to self.markets, scaled by num/den: the part of that vault that belongs to
        the vault this report is about."""
        via = via or []
        if len(via) > 2 * MAX_NESTING or addr in via:
            self.uncovered.append(f"{addr} nests vaults more than {MAX_NESTING} deep or loops back: not followed")
            return
        version = self.version(addr)
        via = via + [addr]
        if version.startswith("MetaMorpho"):
            ids: list[bytes] = []
            for q in ("withdrawQueue", "supplyQueue"):
                n = self._must_uint(addr, f"{q}Length()")
                ids += [r[:32] for r in self._must([(addr, _sel(f"{q}(uint256)") + i.to_bytes(32, "big")) for i in range(n)], f"{q} of {addr}")]
            self._read_markets(self.prober._addr(addr, "MORPHO()"), list(dict.fromkeys(ids)), addr, num, den, via, caps_of=addr)
            return
        n = self._must_uint(addr, "adaptersLength()")
        for r in self._must([(addr, _sel("adapters(uint256)") + i.to_bytes(32, "big")) for i in range(n)], f"adapters of {addr}"):
            self._read_adapter(_a(r), num, den, via)

    def _read_adapter(self, adapter: str, num: int, den: int, via: list[str]) -> None:
        n = self._uint(adapter, "marketIdsLength()")
        if n is not None:       # MorphoMarketV1AdapterV2: a list of market ids, positions held by the adapter
            ids = [r[:32] for r in self._must([(adapter, _sel("marketIds(uint256)") + i.to_bytes(32, "big")) for i in range(n)], f"marketIds of {adapter}")]
            self._read_markets(self.prober._addr(adapter, "morpho()"), ids, adapter, num, den, via + [adapter])
            return
        n = self._uint(adapter, "marketParamsListLength()")
        if n is not None:       # MorphoMarketV1Adapter: a list of market params; the id is their keccak256
            rows = self._must([(adapter, _sel("marketParamsList(uint256)") + i.to_bytes(32, "big")) for i in range(n)], f"marketParamsList of {adapter}")
            ids = [bytes(Web3.keccak(r[:160])) for r in rows]
            self._read_markets(self.prober._addr(adapter, "morpho()"), ids, adapter, num, den, via + [adapter])
            return
        inner = self.prober._addr(adapter, "morphoVaultV1()")
        if inner:               # MorphoVaultV1Adapter: shares of another vault, a V1 or a V2 behind the same interface
            shares, supply = (_u(r) for r in self._must([(inner, _sel("balanceOf(address)") + _pad(adapter)), (inner, _sel("totalSupply()"))],
                                                        f"shares of {inner} held by adapter {adapter}"))
            if shares and supply:
                self.read_vault(inner, num * shares, den * supply, via + [adapter])
            return
        real = self._uint(adapter, "realAssets()")
        if real is not None:
            self.unmapped_assets += real * num // den
        self.uncovered.append(f"adapter {adapter} is not a Morpho market or vault adapter; its "
                              + (f"realAssets() of {real * num // den} (raw loan-token units)" if real is not None else "holdings (realAssets() does not answer)")
                              + " are not mapped to collateral")

    def _read_markets(self, morpho: str | None, ids: list[bytes], holder: str, num: int, den: int, via: list[str], caps_of: str | None = None) -> None:
        if not ids:
            return
        if not morpho:
            raise ProbeRpcError(f"{holder} does not name its Morpho Blue contract at block {self.block}")
        calls = ([(morpho, _sel("idToMarketParams(bytes32)") + i) for i in ids] + [(morpho, _sel("position(bytes32,address)") + i + _pad(holder)) for i in ids]
                 + [(morpho, _sel("market(bytes32)") + i) for i in ids] + [(caps_of, _sel("config(bytes32)") + i) for i in ids if caps_of])
        res = self._must(calls, f"Morpho Blue markets of {holder}")
        k = len(ids)
        for j, mid in enumerate(ids):
            params, pos, mk = res[j], res[k + j], res[2 * k + j]
            key = "0x" + mid.hex()
            if _u(params, 0) == 0:
                self.uncovered.append(f"market {key} listed by {holder} does not exist on Morpho Blue {morpho}")
                continue
            assets = _u(pos) * (_u(mk, 0) + VIRTUAL_ASSETS) // (_u(mk, 1) + VIRTUAL_SHARES) * num // den
            m = self.markets.get(key)
            if m is None:
                m = self.markets[key] = Market(key, _a(params[0:32]), _a(params[32:64]), _a(params[64:96]), _a(params[96:128]), _u(params, 4))
            m.assets += assets
            if caps_of:
                cap = _u(res[3 * k + j]) & (2**184 - 1)
                m.cap = cap if m.cap is None else m.cap + cap
            m.via = m.via or via

    def _token(self, addr: str, parent: str | None = None) -> Token:
        names, _ = self._guard(f"symbol, name and decimals of {addr}",
                               lambda: self.prober._batch_calls([(addr, _sel("symbol()")), (addr, _sel("name()")), (addr, _sel("decimals()"))]))
        names = names or [None, None, None]
        dec = _u(names[2]) if names[2] and len(names[2]) >= 32 and _u(names[2]) < 78 else None
        return Token(addr, _text(names[0]) or "?", _text(names[1]) or "", dec, parent=parent)

    # ---- the walk, with a clean rollback when a read fails ----
    def _guard(self, what: str, fn):
        """Run fn. On a failed read, put the prober back as it was (a half-probed node would read as a contract with no
        owner), wait and retry; after the last try, record the failure. Returns (result, error)."""
        err = None
        for attempt in range(5):
            saved = (copy.deepcopy(self.prober.seen), set(self.prober.replayed), list(self.prober.incomplete), dict(self._code))
            try:
                return fn(), None
            except READ_ERRORS as e:
                self.prober.seen, self.prober.replayed, self.prober.incomplete, self._code = saved
                err = redact(e)
                limited = any(w in err.lower() for w in ("429", "too many", "rate"))
                if attempt == (4 if limited else 2) or any(g in err.lower() for g in GONE):
                    break
                self.log(f"  {what}: {err}; retrying")
                time.sleep((10 if limited else 2) * (attempt + 1))
        self.failed.append(f"{what}: {err}")
        return None, err

    def _probe_token(self, t: Token) -> None:
        t.getters, t.registry = {}, None
        self.prober.probe(t.address)
        if self.prober._addr(t.address, "SY()"):
            t.pendle_yt = self.prober._addr(t.address, "YT()")
        for sig in (*MINT_GETTERS, *PAUSE_GETTERS, *OWNER_GETTERS):
            a = self.prober._addr(t.address, sig)
            if a and a != t.address:
                t.getters[sig] = a
                self.prober.probe(a)
        for sig in ACL_GETTERS:
            a = self.prober._addr(t.address, sig)
            if a and a != t.address and self.prober._supports_access_control(a):
                t.registry = a
                self.prober.probe(a)
                break
        t.erc4626 = all(self.prober._call(t.address, s) is not None for s in ("asset()", "totalAssets()"))
        t.sim_extra = [a for a in dict.fromkeys(self.prober._addr(t.address, g) for g in SIM_GETTERS) if a and a != t.address]

    def _underlying(self, t: Token) -> str | None:
        for sig in UNDERLYING_GETTERS:
            a = self.prober._addr(t.address, sig)
            if a and a not in (t.address, self.vault) and self.code(a):
                return a
        return None

    def reach(self, root: str) -> list[Node]:
        """root and every node the probe found above it: its upgrade admin, owner, admins, named keys and role holders,
        and theirs. A Safe's signers are left out: they act through the Safe."""
        out: dict[str, Node] = {}
        stack = [root]
        while stack:
            a = stack.pop(0)
            n = self.prober.seen.get(a)
            if n is None or a in out:
                continue
            out[a] = n
            stack += [x for x in (n.proxy_admin, n.owner, n.pending_owner, n.admin, n.beacon, n.authority, n.kernel, n.authorizer,
                                  n.dao, n.emergency) if x]
            stack += [*n.wards, *n.named.values(), *n.safe_modules, *(h for hs in n.roles.values() for h in hs),
                      *(h for hs in n.am_roles.values() for h, _ in hs)]
        return list(out.values())

    def _token_reach(self, t: Token) -> list[Node]:
        nodes = {n.address: n for n in self.reach(t.address)}
        for a in [*t.getters.values(), *([t.registry] if t.registry else [])]:
            nodes.update({n.address: n for n in self.reach(a)})
        return list(nodes.values())

    # ---- roles and simulations ----
    def _explorer_logs(self, params: dict) -> list | None:
        """One page of an Etherscan-style getLogs, from the first explorer that answers. An explorer that rate-limits
        for longer than a short wait is dropped for the rest of the run."""
        while self._explorers:
            url = self._explorers[0]
            for attempt in range(3):
                time.sleep(0.4)      # keyless limits are low; a steady pace gets more done than bursts and waits
                try:
                    r = requests.get(url, params=params, timeout=20)
                    rows = r.json().get("result")
                except (requests.RequestException, ValueError, AttributeError):
                    r, rows = None, None
                if isinstance(rows, list):
                    self.explorers_used.add(url.split("/")[2])
                    return rows
                reset = int((getattr(r, "headers", None) or {}).get("x-ratelimit-reset") or 0)
                if r is not None and r.status_code == 429 and reset > 30_000:
                    break
                time.sleep(min(reset / 1000, 30) if reset else 2 * (attempt + 1))
            self.explorers_dropped.append(url.split("/")[2])
            self._explorers.pop(0)
        return None

    def _grantees(self, addr: str) -> dict[bytes, set[str]] | None:
        """Every (role, account) ever granted on addr up to the pinned block, from an explorer's log index; None when
        there is no explorer for this chain or none answers."""
        out: dict[bytes, set[str]] = {}
        for page in range(1, 11):
            rows = self._explorer_logs({"module": "logs", "action": "getLogs", "fromBlock": 0, "toBlock": self.block,
                                        "address": addr, "topic0": ROLE_GRANTED, "page": page, "offset": 1000})
            if rows is None:
                self.explorer_error = (f"no explorer answered for {addr}: {', '.join(self.explorers_dropped)} stopped answering"
                                       if self.explorers_dropped else "no explorer for this chain")
                return None
            for x in rows:
                t = x.get("topics") or []
                if len(t) >= 3 and t[1] and t[2]:
                    out.setdefault(bytes.fromhex(t[1][2:].rjust(64, "0")), set()).add(Web3.to_checksum_address("0x" + t[2][-40:]))
            if len(rows) < 1000:
                return out
        self.explorer_error = f"{addr} has more than 10,000 role grants; only the first 10,000 were read"
        return None

    def _role_hints(self, only: list[str] | None = None) -> None:
        """For every AccessControl contract found that does not list its members (or those in `only`), test each account
        an explorer saw granted a role, at the pinned block."""
        nodes = [n for n in self.prober.seen.values() if n.kind not in ("eoa", "safe", "access-manager") and n.address not in self.hinted
                 and (only is None or n.address in only)]
        if not nodes:
            return
        res = self.prober._batch_calls([(n.address, _sel("hasRole(bytes32,address)") + bytes(64)) for n in nodes]
                                       + [(n.address, _sel("getRoleMemberCount(bytes32)") + bytes(32)) for n in nodes])
        done = set()      # added to self.hinted only once every read worked: a retry starts from a rolled-back prober
        for n, sup, count in zip(nodes, res, res[len(nodes):]):
            if count is not None and sup is not None:
                self.enumerable.add(n.address)
            if sup is None or len(sup) != 32 or count is not None:     # not AccessControl, or it lists its members itself
                continue
            grants = self._grantees(n.address)
            if grants is None:
                continue
            names = {bytes(v): k for k, v in ROLES.items()} | {v: k for k, v in EXTRA_ROLES.items()}
            names |= {bytes.fromhex(h[2:]): g for h, g in self.prober.role_names(n.address).items()}
            pairs = [(role, who) for role, accounts in grants.items() for who in sorted(accounts) if who != ZERO]
            held = self.prober._batch_calls([(n.address, _sel("hasRole(bytes32,address)") + role + _pad(who)) for role, who in pairs])
            if any(r is None for r in held):
                raise ProbeRpcError(f"hasRole on {n.address}: no answer at block {self.block}")
            for (role, who), r in zip(pairs, held):
                if _u(r):
                    name = names.get(role, "0x" + role.hex())
                    if who not in n.roles.get(name, []):
                        n.roles.setdefault(name, []).append(who)
            done.add(n.address)
            self.prober._role_findings(n)
        self.hinted |= done

    def _named_roles(self, t: Token, cands: list[str]) -> None:
        """Mint and pause roles by name: the common ones and every bytes32 getter in the verified ABI (MINT_OPERATOR_ROLE
        and the like). Enumerated when the contract lists members, else tested against every address in the report."""
        where = t.registry or t.address
        if not self.prober._supports_access_control(where):
            return
        names = {k: bytes(v) for k, v in ROLES.items()} | EXTRA_ROLES
        declared = {"DEFAULT_ADMIN_ROLE"}        # roles known to exist: a missing holder is then an open question, not noise
        for a in dict.fromkeys([t.address, where]):
            found = {g: bytes.fromhex(h[2:]) for h, g in self.prober.role_names(a).items()}
            names |= found
            declared |= set(found)
        n = self.prober.seen[where]
        enumerable = self.prober._call_args(where, "getRoleMemberCount(bytes32)", bytes(32)) is not None
        for name, role in names.items():
            if not (MINT_ROLE.search(name) or PAUSE_ROLE.search(name) or name == "DEFAULT_ADMIN_ROLE"):
                continue
            if enumerable:
                k = self._uint(where, "getRoleMemberCount(bytes32)", role) or 0
                rows = self.prober._batch_calls([(where, _sel("getRoleMember(bytes32,uint256)") + role + i.to_bytes(32, "big")) for i in range(min(k, 50))])
                holders = [_a(r) for r in rows if r and len(r) >= 32]
                t.role_scope[name] = "listed by the contract" if len(holders) == k else f"{len(holders)} of {k} members read"
            else:
                res = self.prober._batch_calls([(where, _sel("hasRole(bytes32,address)") + role + _pad(c)) for c in cands])
                holders = [c for c, r in zip(cands, res) if r and len(r) == 32 and _u(r)]
                t.role_scope[name] = f"hasRole tested for {len(cands)} addresses found in this report; the contract does not list members"
            if where in self.prober.replayed:
                t.role_scope[name] = "replayed from RoleGranted/RoleRevoked logs"
            elif where in self.hinted and not enumerable:
                t.role_scope[name] = "every account the explorer saw granted a role, confirmed with hasRole at this block"
            new = [h for h in holders if h not in n.roles.get(name, [])]
            if new:
                n.roles[name] = n.roles.get(name, []) + new
            if (not enumerable and where not in self.prober.replayed and where not in self.hinted and name in declared
                    and not n.roles.get(name)):
                t.open.append(f"{name} on `{where}`: no holder among the {len(cands)} addresses tested, and the contract does not list members")
        self.prober._role_findings(n)

    def _passes(self, target: str, sig: str, types: list[str], who: list[str]) -> list[str]:
        def fill(ty: str):
            if ty == "address":
                return STRANGER
            if ty.startswith("bytes"):
                return bytes(int(ty[5:]) if ty[5:] else 0)
            return {"bool": True, "string": ""}.get(ty, 1)
        args = [fill(ty) for ty in types]
        data = _sel(sig) + (abi_encode(types, args) if types else b"")
        return [w for w in who if self.prober._try_call({"from": w, "to": target, "data": data}) is not None]

    def _abi_fns(self, n: Node, power: str) -> dict[str, list[str]]:
        """Mint-like or pause-like functions in the verified ABI of the token or its implementation, with plain arguments."""
        from .decode import verified_abi
        abi: list = []
        for a in (n.address, n.implementation or n.clone_of):
            if a:
                abi += verified_abi(self.chain_id, a) or []
        out = {}
        for f in abi:
            types = [i["type"] for i in f.get("inputs") or []]
            if (f.get("type") == "function" and f.get("stateMutability") not in ("view", "pure") and ABI_FN[power].search(f.get("name", ""))
                    and not re.search(r"^unpause", f.get("name", ""), re.I) and all(SIMPLE_ARG.match(ty) for ty in types)):
                out[f"{f['name']}({','.join(types)})"] = types
        return out

    def _present(self, n: Node, sig: str) -> bool:
        """The function's selector is in the token's code or its implementation's (a dispatcher pushes every selector)."""
        impl = n.implementation or n.clone_of
        return _sel(sig) in self.code(n.address) + self.code(impl)

    # ---- describing control ----
    def who(self, addr: str, depth: int = 0, seen: frozenset = frozenset()) -> tuple[str, str, int, bool]:
        """How an address acts: (full text, short text, seconds of timelock delay on the way, resolved). The walk follows
        a contract's owner or admin, and a timelock's proposers, up to a key or a Safe. resolved is False when it ends at
        something whose control the probe could not read; the delay is then a floor, not a fact."""
        n = self.prober.seen.get(addr)
        a = f"`{addr}`"
        if n is None and self._frozen:
            return f"{a} (not probed)", "not probed", 0, False
        n = n or self.prober.probe(addr)
        if n.kind == "eoa":
            return f"EOA {a}", "EOA", 0, True
        if n.kind == "safe":
            k = f"{n.safe_threshold}-of-{len(n.safe_owners)} Safe" + (f" with {len(n.safe_modules)} module(s)" if n.safe_modules else "")
            return f"{k} {a}", k, 0, True
        if addr in seen:        # a proposer the timelock itself controls, say: it adds no way around the timelock
            return f"back to {a}", "loop", 0, True
        if depth >= 5:
            return f"contract {a} (walk stopped)", "unresolved", 0, False
        seen = seen | {addr}
        delay = 0
        if n.kind == "timelock" and addr not in self.hinted and not self._frozen and EXPLORERS.get(self.chain_id):
            self._role_hints([addr])        # a timelock found late (through a simulation): its proposers from the index too
        if n.kind in ("timelock", "legacy-timelock"):
            delay = n.delay or 0
            label = f"{_dur(delay)} timelock" if delay else "timelock with no delay"
            nxt = [h for h in n.roles.get("PROPOSER_ROLE", []) if h != ZERO] or [x for x in (n.owner, n.admin) if x and x != addr]
            if not nxt:
                return f"{label} {a} (no proposer found among the addresses tested; it does not list them)", label, delay, False
            if n.roles.get("PROPOSER_ROLE") and not {n.address} & (self.prober.replayed | self.hinted | self.enumerable):
                label += " (proposers found among the addresses tested)"
        elif n.kind == "aragon-app":
            return f"Aragon app {a}: changes go through the ACL of DAO kernel `{n.kernel}`", "Aragon DAO", 0, False
        elif n.kind == "access-manager":
            return f"AccessManager {a}", "AccessManager", 0, False
        else:
            label = "contract"
            nxt = [x for x in dict.fromkeys((n.owner, n.admin, n.authority)) if x and x != addr] or \
                  [h for h in n.roles.get("DEFAULT_ADMIN_ROLE", []) if h not in (addr, ZERO)]
            if not nxt and addr not in self._governor and not self._frozen:
                self._governor[addr] = all(self.prober._call(addr, g) is not None for g in ("votingPeriod()", "proposalThreshold()"))
            if not nxt and self._governor.get(addr):
                return f"Governor {a} (token-holder vote)", "Governor vote", 0, True
            if not nxt:
                return f"contract {a} (no owner, admin or DEFAULT_ADMIN_ROLE holder found)", "contract", 0, False
        subs = [self.who(x, depth + 1, seen) for x in nxt[:4]]
        full = f"{label} {a} → " + (" / ".join(s[0] for s in subs) if len(subs) == 1 else "[" + " / ".join(s[0] for s in subs) + "]")
        subs = [x for x in subs if x[1] != "loop"] or subs     # all loops: the walk ends here
        short = " / ".join(dict.fromkeys(s[1] for s in subs))
        if label != "contract":
            short = f"{label} → {short}"
        return full, short, delay + min(s[2] for s in subs), all(s[3] for s in subs) and len(nxt) <= 4

    def _cell(self, addrs: list[str]) -> str:
        parts = []
        for x in addrs:
            _, short, delay, ok = self.who(x)
            parts.append(short + ("" if "timelock" in short else ", no delay" if ok else ", delay not established"))
        return "; ".join(dict.fromkeys(parts)) or "-"

    def _line(self, what: str, addr: str) -> str:
        full, _, delay, ok = self.who(addr)
        wait = f"{_dur(delay)} timelock delay on this path" if delay else ("no timelock on this path" if ok else "delay not established")
        return f"{what}: {full} ({wait})"

    def analyse(self, t: Token, cands: list[str]) -> None:
        t.powers, t.open, t.findings, t.role_scope = {}, [], [], {}
        n = self.prober.seen[t.address]
        if self.roles_error is None:
            self._named_roles(t, cands)
        reach = self._token_reach(t)
        actors = list(dict.fromkeys([x.address for x in reach if x.address != t.address] + t.sim_extra))
        # owner and admins: owner(), a separate admin(), DEFAULT_ADMIN_ROLE on the token or its role registry
        lines, holders = [], []
        if n.owner:
            lines.append(self._line("owner()", n.owner))
            holders.append(n.owner)
        if n.pending_owner:
            lines.append(self._line("pendingOwner() (can accept ownership)", n.pending_owner))
        if n.admin and n.admin != n.proxy_admin:
            lines.append(self._line("admin()", n.admin))
            holders.append(n.admin)
        for sig in OWNER_GETTERS:
            if t.getters.get(sig) and t.getters[sig] not in holders:
                lines.append(self._line(sig, t.getters[sig]))
                holders.append(t.getters[sig])
        for where in dict.fromkeys([t.address, *([t.registry] if t.registry else [])]):
            for h in self.prober.seen[where].roles.get("DEFAULT_ADMIN_ROLE", []):
                if h != ZERO:
                    lines.append(self._line("DEFAULT_ADMIN_ROLE" + (f" on registry `{where}`" if where != t.address else ""), h))
                    holders.append(h)
        if t.role_scope.get("DEFAULT_ADMIN_ROLE"):
            lines.append(f"DEFAULT_ADMIN_ROLE: {t.role_scope['DEFAULT_ADMIN_ROLE']}")
        if holders:
            t.powers["owner"] = (self._cell(list(dict.fromkeys(holders))), lines)
        elif any(x.startswith("DEFAULT_ADMIN_ROLE") for x in t.open):
            t.powers["owner"] = ("not established", lines + ["owner() does not answer"])
        else:
            t.powers["owner"] = ("none", lines + ["owner() does not answer" + ("; no DEFAULT_ADMIN_ROLE holder" if t.role_scope else "")])
        # upgrade
        if n.clone_of and not n.beacon:
            t.powers["upgrade"] = ("not upgradeable", [f"EIP-1167 clone of `{n.clone_of}`: its code is fixed"])
        elif n.proxy_admin:
            how = f" (stored in factory `{n.admin_factory}`)" if n.admin_factory else f" (through beacon `{n.beacon}`)" if n.beacon else ""
            t.powers["upgrade"] = (self._cell([n.proxy_admin]), [self._line(f"upgrade admin{how}", n.proxy_admin), f"implementation `{n.implementation}`"])
        elif n.implementation:
            # in the implementation (UUPS), or in the proxy itself behind a governor() or similar check (Origin and others)
            sigs = [s for s in UUPS_FNS if _sel(s) in self.code(n.implementation) + self.code(t.address)]
            data_for = {"upgradeToAndCall(address,bytes)": ["address", "bytes"], "upgradeTo(address)": ["address"]}
            who = []
            for s in sigs:
                data = _sel(s) + abi_encode(data_for[s], [n.implementation, b""][:len(data_for[s])])
                who += [w for w in [*actors, STRANGER] if w not in who and self.prober._try_call({"from": w, "to": t.address, "data": data}) is not None]
            if STRANGER in who:
                t.powers["upgrade"] = ("open to anyone", [f"{sigs[0]} passes from an address with no role in simulation"])
            elif who:
                t.powers["upgrade"] = (self._cell(who), [f"implementation `{n.implementation}`; the proxy's upgrade function passes in simulation from:"]
                                       + [self._line("  upgrader", w) for w in who])
            else:
                t.powers["upgrade"] = ("not established", [f"proxy with implementation `{n.implementation}` and no admin in the ERC-1967 or "
                                                           "ZeppelinOS admin slots: the upgrade check lives in the implementation (UUPS or custom)"])
                t.open.append("who can upgrade: no address found in this report passes the upgrade function in simulation")
        elif n.kind == "aragon-app":
            t.powers["upgrade"] = ("Aragon DAO", [f"upgrades are granted in the ACL of DAO kernel `{n.kernel}` (APP_MANAGER_ROLE), normally by vote"])
        else:
            custom = next((s for s in ("implementation()", "getImplementation()", "masterCopy()") if self.prober._addr(t.address, s)), None)
            if custom:
                t.powers["upgrade"] = ("not established", [f"answers {custom} = `{self.prober._addr(t.address, custom)}` with empty proxy slots: a custom proxy"])
                t.open.append(f"who can upgrade: custom proxy ({custom}), upgrade path not resolved")
            else:
                t.powers["upgrade"] = ("not a proxy", ["no implementation in the ERC-1967, ZeppelinOS or beacon slots and not an EIP-1167 clone"])
        # mint and pause
        roles = dict(n.roles)
        if t.registry:
            roles |= {f"{k} (on registry `{t.registry}`)": v for k, v in self.prober.seen[t.registry].roles.items()}
        for power, fns, pattern, getters in (("mint", MINT_FNS, MINT_ROLE, MINT_GETTERS), ("pause", PAUSE_FNS, PAUSE_ROLE, PAUSE_GETTERS)):
            fns = {**fns, **self._abi_fns(n, power)}
            skip = NOT_ADMIN_MINT if (t.erc4626 or t.pendle_yt) else set()
            present = [s for s in fns if s not in skip and self._present(n, s)]
            lines, holders = [], []
            for name, hs in roles.items():
                if pattern.search(name):
                    scope = t.role_scope.get(name.split(" (on registry")[0], "")
                    lines += [self._line(name, h) for h in hs if h != ZERO] + ([f"{name}: {scope}"] if scope else [])
                    holders += [h for h in hs if h != ZERO]
            for sig, a in t.getters.items():
                if sig in getters:
                    lines.append(self._line(GETTER_LABEL.get(sig, sig), a))
                    holders.append(a)
            if power == "mint":
                for sig in MINTER_CHECKS:
                    if not self._present(n, sig):
                        continue
                    res = self.prober._batch_calls([(t.address, _sel(sig) + _pad(c)) for c in cands])
                    found = [c for c, r in zip(cands, res) if r and len(r) >= 32 and _u(r) == 1]
                    lines += [self._line(f"{sig.split('(')[0]}() is true for", c) for c in found]
                    lines.append(f"{sig}: tested for {len(cands)} addresses found in this report; the token does not list its minters")
                    holders += found
                    if not found:
                        t.open.append(f"who can mint: {sig} is in the code, and none of the {len(cands)} addresses tested is a minter")
            passes = {s: self._passes(t.address, s, fns[s], [*actors, STRANGER]) for s in present}
            for s, who in passes.items():
                if STRANGER in who:
                    lines.append(f"{s} passes in simulation from an address with no role: it is open to anyone")
                for w in who:
                    if w != STRANGER:
                        lines.append(self._line(f"{s} passes in simulation from", w))
                        holders.append(w)
            if power == "pause" and n.paused:
                lines.insert(0, "paused() is true at this block")
            holders = list(dict.fromkeys(holders))
            if any(STRANGER in w for w in passes.values()):
                cell = "open to anyone"
            elif n.kind == "aragon-app" and not holders:
                cell = "Aragon ACL"
                lines = [f"{power} permissions are granted in the ACL of DAO kernel `{n.kernel}`, normally by vote; ACL holders are not listed here"]
            elif holders:
                cell = self._cell(holders)
            elif present:
                cell = "not established"
                t.open.append(f"who can {power}: {', '.join(present)} is in the code, but no address in this report passes it in "
                              f"simulation and no {power} role or getter was found")
            elif power == "mint" and t.pendle_yt:
                cell = "deposits only"
                lines.append(f"Pendle PT: minted by its YT `{t.pendle_yt}` against deposits of SY (mintByYT)")
            elif power == "mint" and t.erc4626:
                cell = "deposits only"
                lines.append("ERC-4626: shares are minted against deposits of the underlying asset")
            else:
                cell = f"no {power} function found"
                lines.append(f"no {power} function among {', '.join(fns)} (nor any in a verified ABI), no {power} role and no {power} getter")
            if power == "pause" and n.paused:
                cell = "PAUSED; " + cell
            t.powers[power] = (cell, lines)
        t.findings = list(dict.fromkeys(f"`{x.address}`: {note}" for x in reach for note in x.notes if not note.startswith("AccessManager 0x")))
        t.open = list(dict.fromkeys(t.open))
        if self.roles_error:
            t.open.append(f"role holders: the role check failed ({self.roles_error})")

    # ---- the whole run ----
    def _read_vault_state(self) -> None:
        self.markets, self.uncovered, self.unmapped_assets, self.failed = {}, [], 0, []
        self.version_name = self.version(self.vault)
        meta = self._must([(self.vault, _sel("asset()")), (self.vault, _sel("totalAssets()"))], f"vault {self.vault}")
        self.asset, self.total = _a(meta[0]), _u(meta[1])
        v = self._token(self.vault)
        self.vault_name, self.vault_symbol = v.name, v.symbol
        self.loan = self._token(self.asset)
        self.idle = _u(self._must([(self.asset, _sel("balanceOf(address)") + _pad(self.vault))], "idle balance")[0])
        self.lost = self._uint(self.vault, "lostAssets()") if self.version_name == "MetaMorpho V1.1" else None
        self.vault_roles = {k: self.prober._addr(self.vault, f"{k}()") for k in ("owner", "curator", "guardian")}
        self.vault_timelock = self._uint(self.vault, "timelock()") if self.version_name.startswith("MetaMorpho") else None
        self.v2_timelocks = {}
        if self.version_name == "Morpho Vault V2":      # per-function timelocks on the curator's risk-raising calls
            fns = ("addAdapter(address)", "increaseAbsoluteCap(bytes,uint256)", "increaseRelativeCap(bytes,uint256)", "setIsAllocator(address,bool)")
            res = self.prober._batch_calls([(self.vault, _sel("timelock(bytes4)") + _sel(f) + bytes(28)) for f in fns])
            self.v2_timelocks = {f.split("(")[0]: _u(r) for f, r in zip(fns, res) if r and len(r) >= 32}
        self.log(f"{self.vault} is a {self.version_name}; reading markets at block {self.block}")
        self.read_vault(self.vault)

    def run(self) -> CollateralReport:
        _retry(self._read_vault_state, self.log)
        by_token: dict[str, Token] = {}
        for m in sorted(self.markets.values(), key=lambda m: -m.assets):
            if int(m.collateral, 16) == 0:
                continue
            if m.collateral not in by_token:
                by_token[m.collateral] = self._token(m.collateral)
            by_token[m.collateral].markets.append(m)
            by_token[m.collateral].assets += m.assets
        self.tokens = sorted(by_token.values(), key=lambda t: (-t.assets, t.symbol))
        for t in self.tokens:
            self.log(f"probing {t.symbol} {t.address}")
            cur, depth = t, 0
            while cur is not None:
                _, cur.error = self._guard(f"{cur.symbol} {cur.address}", lambda c=cur: self._probe_token(c))
                under, _ = (None, None) if cur.error or depth >= 3 else self._guard(f"underlying of {cur.symbol}", lambda c=cur: self._underlying(c))
                if under and under in by_token:
                    cur.wraps_ranked = under
                elif under:
                    cur.wraps = self._token(under, parent=cur.address)
                cur, depth = cur.wraps, depth + 1
        for m in self.markets.values():
            if int(m.oracle, 16) and m.oracle not in self.oracles:
                self.log(f"probing oracle {m.oracle}")
                res, err = self._guard(f"oracle {m.oracle}", lambda o=m.oracle: self._probe_oracle(o))
                self.oracles[m.oracle] = res or {"error": err}
        for a in [x for x in self.vault_roles.values() if x]:
            self._guard(f"vault role {a}", lambda a=a: self.prober.probe(a))
        self.log("reading role grants from the explorer")
        _, err = self._guard("role grants from the explorer", self._role_hints)
        self.explorer_error = self.explorer_error or err
        cands = list(dict.fromkeys([*self.prober.seen, *(o for n in list(self.prober.seen.values()) for o in n.safe_owners)]))
        _, self.roles_error = self._guard("role check", lambda: self.prober.check_roles(cands))
        if self.roles_from_logs:
            for t in self.all_tokens():
                where = t.registry or t.address
                if not t.error and self.prober.seen.get(where) and self.prober._supports_access_control(where):
                    _, err = self._guard(f"role history of {where}", lambda w=where: self.prober.role_history(w, None, self.logs_w3, log=self.log, to_block=self.block))
                    if err:
                        t.open.append(f"role history could not be read ({err}): role holders may be incomplete")
        cands = list(dict.fromkeys([*self.prober.seen, *(o for n in list(self.prober.seen.values()) for o in n.safe_owners)]))
        for t in self.all_tokens():
            if not t.error:
                _, err = self._guard(f"analysis of {t.symbol} {t.address}", lambda t=t: self.analyse(t, cands))
                if err:
                    t.error, t.powers = err, {}
        for o, info in self.oracles.items():
            if not info.get("error"):
                res, err = self._guard(f"controllers of oracle {o}", lambda o=o: self._oracle_line(o))
                self.oracle_lines[o] = res or ("read failed", [f"read failed: {err}"])
        for k, a in self.vault_roles.items():
            if a and a in self.prober.seen:
                res, _ = self._guard(f"vault {k}", lambda a=a: self.who(a)[0])
                self.vault_role_lines[k] = res or f"`{a}` (read failed)"
        self._frozen = True
        return self

    def _probe_oracle(self, addr: str) -> dict:
        n = self.prober.probe(addr)
        feeds = {}
        for g in FEEDS:     # MorphoChainlinkOracleV2 and its forks: immutable themselves, but the feeds they read have owners
            a = self.prober._addr(addr, g)
            if a:
                desc = _text(self.prober._call(a, "description()"))
                if not desc and g.endswith("VAULT()"):
                    desc = _text(self.prober._call(a, "symbol()"))
                feeds[g[:-2]] = (a, desc)
                self.prober.probe(a)
        return {"node": n, "feeds": feeds}

    def all_tokens(self) -> list[Token]:
        out = []
        for t in self.tokens:
            cur = t
            while cur is not None:
                out.append(cur)
                cur = cur.wraps
        return out

    @property
    def accounted(self) -> int:
        return sum(m.assets for m in self.markets.values()) + self.idle + self.unmapped_assets

    @property
    def reconciles(self) -> bool:
        return abs(self.accounted - self.total) * 10_000 <= RECONCILE_BPS * max(self.total, 1)

    @property
    def complete(self) -> bool:
        return not (self.failed or self.uncovered or not self.reconciles or any(t.open for t in self.all_tokens()))

    # ---- output ----
    def _oracle_line(self, o: str) -> tuple[str, list[str]]:
        info = self.oracles.get(o) or {}
        if info.get("error"):
            return "read failed", [f"read failed: {info['error']}"]
        n: Node = info["node"]
        lines = []
        cell = self._cell([n.owner]) if n.owner else "none"
        feed_owners = [self.prober.seen[a].owner for a, _ in info["feeds"].values() if self.prober.seen.get(a) and self.prober.seen[a].owner]
        if feed_owners:
            cell += f" (feeds: {self._cell(list(dict.fromkeys(feed_owners)))})"
        lines.append(self._line("owner()", n.owner) if n.owner else "owner(): none")
        if n.proxy_admin:
            lines.append(self._line("upgrade admin", n.proxy_admin))
            cell += f"; upgradeable ({self._cell([n.proxy_admin])})"
        elif n.implementation:
            lines.append(f"proxy with implementation `{n.implementation}` and no admin in the standard slots: upgrade path not resolved")
            cell += "; proxy, upgrade path not resolved"
        for k, (a, desc) in info["feeds"].items():
            fn = self.prober.seen.get(a)
            ctl = []
            if fn is not None and fn.owner:
                ctl.append(f"owner {self.who(fn.owner)[0]}")
            if fn is not None and fn.proxy_admin:
                ctl.append(f"upgrade admin {self.who(fn.proxy_admin)[0]}")
            lines.append(f"{k} `{a}`" + (f" ({desc})" if desc else "") + (": " + "; ".join(ctl) if ctl else ": no owner or upgrade admin found"))
        return cell, lines

    def markdown(self) -> str:
        loan = self.loan.symbol
        when = datetime.fromtimestamp(self.timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        title = self.vault_name or self.vault_symbol
        lines = [f"# {title} collateral report", "",
                 f"Who can mint, upgrade or pause the collateral behind {self.version_name} `{self.vault}` ({self.vault_symbol}) on {self.chain}, "
                 f"ranked by what the vault has lent against each token.", "",
                 "| | |", "|---|---|",
                 f"| Pinned block | {self.block} ({when}): every read in this report is at this block |",
                 f"| Loan asset | {loan} `{self.asset}` |",
                 f"| totalAssets() | {amount(self.total, self.loan.decimals)} {loan} |"]
        for k, a in self.vault_roles.items():
            if a:
                lines.append(f"| {k}() | {self.vault_role_lines.get(k) or f'`{a}` (read failed)'} |")
            elif k == "guardian" and self.version_name.startswith("MetaMorpho"):
                lines.append("| guardian() | none set |")
        if self.vault_timelock is not None:
            lines.append(f"| timelock() | {_dur(self.vault_timelock) if self.vault_timelock else '0'} |")
        if self.v2_timelocks:
            lines.append("| timelock(selector) | " + ", ".join(f"{f} {_dur(d) if d else '0'}" for f, d in self.v2_timelocks.items()) + " |")
        if self.lost:
            lines.append(f"| lostAssets() | {amount(self.lost, self.loan.decimals)} {loan}: assets the vault records as lost to bad debt |")
        lines.append(f"| Accounted for | {amount(self.accounted, self.loan.decimals)} {loan} in {len(self.markets)} markets and idle "
                     f"({amount(self.idle, self.loan.decimals)} idle): " + ("reconciles with totalAssets()" if self.reconciles
                     else f"**does not reconcile with totalAssets()**, off by {amount(abs(self.accounted - self.total), self.loan.decimals)} {loan}") + " |")
        problems = [f"Read failed: {x}" for x in self.failed] + [f"Not covered: {x}" for x in self.uncovered] + \
                   [f"Not covered: {x}" for x in self.prober.incomplete]
        if problems:
            lines += ["", "## Coverage gaps", "", "These parts are missing from the report. Nothing here should be read as safe.", ""]
            lines += [f"- {x}" for x in problems]
        lines += ["", "## Ranked by allocation", "",
                  f"| # | Collateral | Allocated ({loan}) | Share | Owner / admin | Upgrade | Mint | Pause | Findings |", "|---|---|---|---|---|---|---|---|---|"]
        for i, t in enumerate(self.tokens, 1):
            wraps = t.wraps.symbol if t.wraps else self._sym(t.wraps_ranked) if t.wraps_ranked else None
            lines.append(f"| {i} | {t.symbol} `{t.address[:8]}…` | {amount(t.assets, self.loan.decimals)} | {_pct(t.assets, self.total)} | "
                         + self._row(t) + (f"; wraps {wraps}" if wraps else "") + " |")
        idle = [m for m in self.markets.values() if int(m.collateral, 16) == 0]
        if idle:
            lines += ["", "Idle markets (no collateral, nothing borrowed): " + ", ".join(
                f"`{m.id[:10]}…` {amount(m.assets, self.loan.decimals)} {loan}" for m in idle)]
        lines += ["", "In the table and below, `A → B` means B controls A. A delay is a timelock found on-chain on that path."]
        for i, t in enumerate(self.tokens, 1):
            lines += ["", f"## {i}. {t.symbol}: {amount(t.assets, self.loan.decimals)} {loan} ({_pct(t.assets, self.total)})", ""]
            lines += self._token_section(t)
            lines += ["", "| Market | LLTV | Allocated | Cap | Oracle | Oracle owner |", "|---|---|---|---|---|---|"]
            for m in t.markets:
                cap = "-" if m.cap is None else amount(m.cap, self.loan.decimals)
                lines.append(f"| `{m.id[:10]}…` | {m.lltv / 1e16:g}% | {amount(m.assets, self.loan.decimals)} | {cap} | `{m.oracle}` | {(self.oracle_lines.get(m.oracle) or self._oracle_line(m.oracle))[0]} |")
            w = t.wraps
            while w is not None:
                lines += ["", f"### {t.symbol} wraps {w.symbol} `{w.address}`", ""] + self._token_section(w)
                w = w.wraps
        if self.oracles:
            lines += ["", "## Oracles", ""]
            notes: list[str] = []
            for o in self.oracles:
                users = sorted({self._sym(m.collateral) for m in self.markets.values() if m.oracle == o})
                lines.append(f"- `{o}` ({', '.join(users)})")
                lines += [f"  - {x}" for x in (self.oracle_lines.get(o) or self._oracle_line(o))[1]]
                if not (self.oracles[o] or {}).get("error"):
                    feeds = [a for a, _ in self.oracles[o]["feeds"].values()]
                    notes += [f"`{x.address}`: {note}" for r in (o, *feeds) for x in self.reach(r) for note in x.notes]
            if notes:
                lines += ["", "Findings on the oracles and their feeds:", ""] + [f"- {x}" for x in dict.fromkeys(notes)]
        lines += ["", "## How to read this", "",
                  "- Allocations are the vault's Morpho Blue supply positions at each market's last accrual, so they trail totalAssets() by the interest since.",
                  "- Owner and upgrade admin come from owner() and the proxy slots (ERC-1967, ZeppelinOS, beacon, factory adminOf); the probe then walks "
                  "each controller up to a key or a Safe.",
                  "- Mint and pause holders come from roles (enumerated where the contract lists members, else hasRole for every address in this report), "
                  "getters such as minter(), and eth_call simulations at the pinned block from each controller: a success shows the address can make the "
                  "call, a revert shows nothing.",
                  (f"- On contracts that do not list role members, the accounts tested include every account the explorer index "
                   f"({', '.join(sorted(self.explorers_used))}) saw granted a role, each confirmed with hasRole at the pinned block."
                   if self.hinted and not self.explorer_error else
                   f"- The explorer's role-grant index could not be fully read ({self.explorer_error or 'no explorer for this chain'}): on contracts "
                   "that do not list role members, only the addresses found in this report were tested."),
                  "- The chain shows an address, not how its key is held: an EOA may be one key or an MPC wallet."]
        lines += ["", f"_Generated by `ownerwatch collateral` {__version__}. Read-only; nothing was sent on-chain._"]
        return "\n".join(lines) + "\n"

    def _sym(self, addr: str) -> str:
        return next((t.symbol for t in self.all_tokens() if t.address == addr), addr[:8])

    def _row(self, t: Token) -> str:
        if t.error:
            return "read failed | read failed | read failed | read failed | **read failed: nothing about this token is known**"
        cells = [t.powers[k][0] for k in ("owner", "upgrade", "mint", "pause")]
        f = f"{len(t.findings)}" if t.findings else "none"
        if t.open:
            f += f"; {len(t.open)} not established"
        return " | ".join(cells) + f" | {f}"

    def _token_section(self, t: Token) -> list[str]:
        out = [f"`{t.address}`" + (f" {t.name}" if t.name else "") + (f", parent `{t.parent}`" if t.parent else ""), ""]
        if t.wraps_ranked:
            out += [f"Wraps {self._sym(t.wraps_ranked)} `{t.wraps_ranked}`, which has its own section above or below.", ""]
        if t.error:
            return out + [f"- **Read failed**: {t.error}. Who controls this token is unknown; it must not be read as safe."]
        for k in ("owner", "upgrade", "mint", "pause"):
            cell, detail = t.powers[k]
            out.append(f"- **{'Owner / admin' if k == 'owner' else k.capitalize()}**: {cell}")
            out += [f"  - {x}" for x in detail]
        if t.findings:
            out.append("- **Findings**")
            out += [f"  - {x}" for x in t.findings]
        else:
            out.append("- **Findings**: none among the addresses reached")
        if t.open:
            out.append("- **Not established**")
            out += [f"  - {x}" for x in t.open]
        return out

    def text(self) -> str:
        loan = self.loan.symbol
        out = [f"{self.vault} {self.version_name} {self.vault_symbol} on {self.chain} at block {self.block}: "
               f"totalAssets {amount(self.total, self.loan.decimals)} {loan}, accounted {amount(self.accounted, self.loan.decimals)}"]
        out += [f"! {x}" for x in [*self.failed, *self.uncovered, *self.prober.incomplete]]
        for i, t in enumerate(self.tokens, 1):
            out.append(f"#{i} {t.symbol} {t.address} {amount(t.assets, self.loan.decimals)} {loan} ({_pct(t.assets, self.total)})")
            for w in [t, *([] if not t.wraps else self._chain(t.wraps))]:
                if w is not t:
                    out.append(f"   wraps {w.symbol} {w.address}")
                if w.error:
                    out.append(f"   READ FAILED: {w.error}")
                    continue
                out += [f"   {k}: {w.powers[k][0]}" for k in ("owner", "upgrade", "mint", "pause")]
                out += [f"   ! {x}" for x in w.findings] + [f"   ? {x}" for x in w.open]
        return "\n".join(out) + "\n"

    @staticmethod
    def _chain(t: Token) -> list[Token]:
        out = []
        while t is not None:
            out.append(t)
            t = t.wraps
        return out

    def config(self, rpc_url: str) -> str:
        """An ownerwatch config that watches the vault, every collateral token and what it wraps, every contract and Safe
        above them, and every oracle."""
        safe_key = {v: k for k, v in SafeQueueWatcher.CHAIN_IDS.items()}.get(self.chain_id)
        contracts, safes, done = [], [], set()

        def add(addr: str, label: str) -> None:
            n = self.prober.seen.get(addr)
            if addr in done or (n is not None and n.kind == "eoa"):
                return
            done.add(addr)
            contracts.append({"address": addr, "label": label})
            if n is not None and n.kind == "safe" and safe_key:
                safes.append({"address": addr, "label": label, "chain": safe_key})

        add(self.vault, f"{self.vault_symbol} vault")
        for t in self.all_tokens():
            add(t.address, f"{t.symbol} collateral" if not t.parent else f"{t.symbol} (wrapped by {self._sym(t.parent)})")
            if not t.error:
                for n in self._token_reach(t):
                    add(n.address, f"{t.symbol} {KIND_LABEL.get(n.kind, 'Contract')}")
        for o, info in self.oracles.items():
            add(o, f"{self._sym(next(m.collateral for m in self.markets.values() if m.oracle == o))} oracle")
            if not info.get("error"):
                for n in self.reach(o)[1:]:
                    add(n.address, f"{self._sym(next(m.collateral for m in self.markets.values() if m.oracle == o))} oracle {KIND_LABEL.get(n.kind, 'Contract')}")
        cfg = {"rpc_url": rpc_url, "chain_name": self.chain, "confirmations": 2, "max_block_range": 2000, "contracts": contracts}
        if safes:
            cfg["safes"] = safes
        cfg["alerts"] = {"discord_webhook": ""}
        head = [f"# ownerwatch config for the collateral of {self.vault_symbol} {self.vault}, from chain state at block {self.block}"]
        head += [f"# NOT COVERED: {x}" for x in [*self.failed, *self.uncovered]]
        return "\n".join(head) + "\n" + yaml.safe_dump(cfg, sort_keys=False)


def build(w3: Web3, vault: str, block: int | None = None, log=None, roles_from_logs: bool = False, logs_w3: Web3 | None = None) -> CollateralReport:
    return CollateralReport(w3, vault, block, log, roles_from_logs, logs_w3).run()
