from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from web3 import Web3

from .events import ADMIN_TOPICS, _norm, topic0


@dataclass
class Token:
    address: str
    symbol: str
    decimals: int | None    # None: read decimals() from the token
    min_amount: float


@dataclass
class Collection:
    address: str
    label: str


@dataclass
class Treasury:
    address: str
    label: str
    tokens: list[Token]
    nfts: list[Collection] = field(default_factory=list)
    min_native_drop: float | None = None   # alert if native balance falls by >= this many ETH between polls


@dataclass
class Contract:
    address: str
    label: str


@dataclass
class Safe:
    address: str
    label: str
    chain: str = "eth"


@dataclass
class Alerts:
    discord_webhook: str = ""
    slack_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    jsonl_path: str = ""           # append every alert as one JSON line to this file (feeds, archives, tests)
    heartbeat_url: str = ""        # GET after every successful poll (healthchecks.io, Better Uptime, cron monitors)
    daily_digest: bool = False     # once a day (UTC) post a one-line summary: alerts by severity, head block, uptime
    min_severity: str = "info"


@dataclass
class CustomEvent:
    name: str
    topic0: str                # 0x + 64 lowercase hex
    severity: str = "high"
    abi: dict | None = None    # None: known only by topic0, so alerts carry the raw log


@dataclass
class Config:
    rpc_url: str
    chain_name: str = "ethereum"
    probe_rpc_url: str = ""         # RPC for `probe` (needs eth_call); defaults to rpc_url
    explorer_url: str = ""          # e.g. https://etherscan.io; alerts then carry a clickable tx link
    poll_interval_seconds: int = 15
    confirmations: int = 2
    max_block_range: int = 2000
    start_block: int | str = "latest"
    state_file: str = "state/cursor.json"
    contracts: list[Contract] = field(default_factory=list)
    treasuries: list[Treasury] = field(default_factory=list)
    safes: list[Safe] = field(default_factory=list)
    safe_api_key: str = ""
    alerts: Alerts = field(default_factory=Alerts)
    custom_events: list[CustomEvent] = field(default_factory=list)

    def labels(self) -> dict[str, str]:
        out = {c.address: c.label for c in self.contracts}
        out.update({t.address: t.label for t in self.treasuries})
        out.update({s.address: s.label for s in self.safes})
        return out


def _addr(a: str) -> str:
    return Web3.to_checksum_address(a)


SHARED_KEYS = ("custom_events", "explorer_url", "poll_interval_seconds", "confirmations", "max_block_range", "start_block", "alerts", "safe_api_key")
CHAIN_KEYS = {"rpc_url", "chain_name", "probe_rpc_url", "state_file", "contracts", "treasuries", "safes", *SHARED_KEYS}
SEVERITY_LEVELS = ("info", "medium", "high", "critical")
# Safe Transaction Service key for a chain_name, so a Safe on a Base config does not default to Ethereum's service.
SAFE_CHAIN_KEYS = {"ethereum": "eth", "mainnet": "eth", "base": "base", "arbitrum": "arb1", "optimism": "oeth", "polygon": "pol",
                   "gnosis": "gno", "bsc": "bnb", "bnb": "bnb", "sepolia": "sep", "avalanche": "avax", "scroll": "scr",
                   "linea": "linea", "mantle": "mantle", "celo": "celo", "aurora": "aurora", "sonic": "sonic",
                   "zksync": "zksync", "berachain": "berachain", "ink": "ink", "unichain": "unichain", "hemi": "hemi"}
SAFE_KEY_ALIASES = {"matic": "pol"}   # the service renamed it; the old key answers 404


MAX_CUSTOM_EVENTS = 50     # each one widens every eth_getLogs filter
_ABI_TYPE = re.compile(r"(address|bool|string|bytes([1-9]|[12][0-9]|3[0-2])?|u?int([1-9][0-9]{0,2})?)(\[[0-9]*\])*")


def _parse_event(text: str) -> tuple[str, dict]:
    """`ForceBurned(address indexed account, uint256 amount)` to its canonical signature and ABI fragment."""
    m = re.fullmatch(r"\s*(?:event\s+)?([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*", text, re.S)
    if not m:
        raise ValueError(f"custom event {text!r}: write it like ForceBurned(address indexed account, uint256 amount)")
    name, body = m.groups()
    if "(" in body:
        raise ValueError(f"custom event {name}: tuples are not supported here; use topic0: and name: to get the raw log")
    inputs = []
    for n, part in enumerate(p for p in body.split(",") if p.strip()):
        words = part.split()
        indexed = "indexed" in words[1:]
        rest = [w for w in words[1:] if w != "indexed"]
        if not _ABI_TYPE.fullmatch(words[0]) or len(rest) > 1:
            raise ValueError(f"custom event {name}: cannot read {part.strip()!r}")
        typ = re.sub(r"^(u?int)(?![0-9])", r"\g<1>256", words[0])
        inputs.append({"name": rest[0] if rest else f"arg{n}", "type": typ, "indexed": indexed})
    if sum(i["indexed"] for i in inputs) > 3:
        raise ValueError(f"custom event {name}: an event has at most 3 indexed arguments")
    signature = f"{name}({','.join(i['type'] for i in inputs)})"
    return signature, {"anonymous": False, "type": "event", "name": name, "inputs": inputs}


def _custom_events(raw: list) -> list[CustomEvent]:
    if len(raw) > MAX_CUSTOM_EVENTS:
        raise ValueError(f"custom_events: {len(raw)} entries, at most {MAX_CUSTOM_EVENTS}")
    out: list[CustomEvent] = []
    for e in raw:
        _known(e, ("event", "topic0", "name", "severity"), f"custom event {e.get('event') or e.get('name')}")
        if bool(e.get("event")) == bool(e.get("topic0")):
            raise ValueError(f"custom event {e.get('event') or e.get('name')}: set either event: or topic0: with name:")
        severity = e.get("severity", "high")
        if severity not in SEVERITY_LEVELS:
            raise ValueError(f"custom event {e.get('event') or e.get('name')}: severity must be one of {', '.join(SEVERITY_LEVELS)}")
        if e.get("event"):
            if e.get("name"):
                raise ValueError(f"custom event {e['event']}: name: goes with topic0:; event: already names it")
            signature, abi = _parse_event(str(e["event"]))
            ev = CustomEvent(abi["name"], _norm(topic0(signature)), severity, abi)
        else:
            t0 = str(e["topic0"]).lower()
            if not re.fullmatch(r"0x[0-9a-f]{64}", t0):
                raise ValueError(f"custom event {e.get('name')}: topic0 must be 0x and 64 hex characters")
            if not e.get("name"):
                raise ValueError(f"custom event {t0}: add name:, it is what the alert shows")
            ev = CustomEvent(str(e["name"]), t0, severity)
        if ev.topic0 in ADMIN_TOPICS:
            raise ValueError(f"custom event {ev.name}: already in the built-in catalog, remove it (see `ownerwatch events`)")
        if ev.topic0 in {o.topic0 for o in out}:
            raise ValueError(f"custom event {ev.name}: listed twice")
        out.append(ev)
    return out


def _known(raw: dict, keys, where: str) -> None:
    """A misspelt key must fail loudly: `discord_webhok` would otherwise mean a watcher that never alerts anyone."""
    unknown = sorted(set(raw) - set(keys))
    if unknown:
        raise ValueError(f"unknown key{'s' if len(unknown) > 1 else ''} in {where}: {', '.join(map(str, unknown))}")


def load_all(path: str | Path) -> list[Config]:
    """One Config per chain. A file with a top-level `chains:` list yields one
    Config per entry; keys in SHARED_KEYS are inherited from the top level."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if "chains" not in raw:
        _known(raw, CHAIN_KEYS, "the config")
        return [_build(raw)]
    _known(raw, {"chains", *SHARED_KEYS}, "the top level of a multi-chain config")
    out = []
    for entry in raw["chains"] or []:
        _known(entry, CHAIN_KEYS, f"chain {entry.get('chain_name', '?')}")
        merged = {k: raw[k] for k in SHARED_KEYS if k in raw}
        merged.update(entry)
        merged.setdefault("state_file", f"state/{merged.get('chain_name', 'chain')}.json")
        out.append(_build(merged))
    if not out:
        raise ValueError("chains: is empty")
    names = [c.chain_name for c in out]
    for values, what in ((names, "chain_name"), ([c.state_file for c in out], "state_file")):
        dup = {v for v in values if values.count(v) > 1}
        if dup:
            raise ValueError(f"two chains share {what} {', '.join(sorted(dup))}: each chain needs its own")
    return out


def load(path: str | Path) -> Config:
    cfgs = load_all(path)
    if len(cfgs) > 1:
        raise ValueError("multi-chain config: use load_all()")
    return cfgs[0]


def _safe_chain(entry: dict, chain_name: str) -> str:
    key = entry.get("chain") or SAFE_CHAIN_KEYS.get(chain_name.lower())
    if not key:
        raise ValueError(f"Safe {entry.get('address')}: add chain: with its Safe service key (eth, base, arb1, oeth, ...); "
                         f"it cannot be inferred from chain_name {chain_name!r}")
    return SAFE_KEY_ALIASES.get(key, key)


def _build(raw: dict) -> Config:
    if not raw.get("rpc_url"):
        raise ValueError("rpc_url is missing")
    chain_name = str(raw.get("chain_name", "ethereum"))
    for c in raw.get("contracts", []) or []:
        _known(c, ("address", "label"), f"contract {c.get('address')}")
    contracts = [Contract(_addr(c["address"]), c.get("label", c["address"])) for c in raw.get("contracts", []) or []]
    treasuries = []
    for t in raw.get("treasuries", []) or []:
        _known(t, ("address", "label", "tokens", "nfts", "min_native_drop"), f"treasury {t.get('address')}")
        for k in t.get("tokens", []) or []:
            _known(k, ("address", "symbol", "decimals", "min_amount"), f"token {k.get('address')}")
        for n in t.get("nfts", []) or []:
            _known(n, ("address", "label"), f"collection {n.get('address')}")
        tokens = [Token(_addr(k["address"]), k.get("symbol", "?"), int(k["decimals"]) if k.get("decimals") is not None else None,
                        float(k.get("min_amount", 0)))
                  for k in t.get("tokens", []) or []]
        nfts = [Collection(_addr(n["address"]), n.get("label", n["address"])) for n in t.get("nfts", []) or []]
        drop = t.get("min_native_drop")
        if drop is not None and float(drop) <= 0:
            raise ValueError(f"treasury {t['address']}: min_native_drop must be above 0, or it alerts on every poll")
        treasuries.append(Treasury(_addr(t["address"]), t.get("label", t["address"]), tokens, nfts,
                                   float(drop) if drop is not None else None))
    for x in raw.get("safes", []) or []:
        _known(x, ("address", "label", "chain"), f"Safe {x.get('address')}")
    safes = [Safe(_addr(x["address"]), x.get("label", x["address"]), _safe_chain(x, chain_name)) for x in raw.get("safes", []) or []]
    _known(raw.get("alerts") or {}, Alerts.__dataclass_fields__, "alerts")
    alerts = Alerts(**(raw.get("alerts") or {}))
    if alerts.min_severity not in SEVERITY_LEVELS:
        raise ValueError(f"min_severity must be one of {', '.join(SEVERITY_LEVELS)}, not {alerts.min_severity!r}")
    if bool(alerts.telegram_bot_token) != bool(alerts.telegram_chat_id):
        raise ValueError("telegram needs both telegram_bot_token and telegram_chat_id")
    start_block = raw.get("start_block", "latest")
    if start_block != "latest" and not (isinstance(start_block, int) and start_block >= 0):
        raise ValueError(f"start_block must be a block number or 'latest', not {start_block!r}")
    cfg = Config(
        rpc_url=raw["rpc_url"],
        chain_name=chain_name,
        probe_rpc_url=str(raw.get("probe_rpc_url", "") or ""),
        explorer_url=str(raw.get("explorer_url", "") or ""),
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 15)),
        confirmations=int(raw.get("confirmations", 2)),
        max_block_range=int(raw.get("max_block_range", 2000)),
        start_block=start_block,
        state_file=raw.get("state_file", "state/cursor.json"),
        contracts=contracts,
        treasuries=treasuries,
        safes=safes,
        safe_api_key=str(raw.get("safe_api_key", "") or ""),
        alerts=alerts,
        custom_events=_custom_events(raw.get("custom_events") or []),
    )
    if not cfg.contracts and not cfg.treasuries and not cfg.safes:
        raise ValueError("config has nothing to watch: add contracts, treasuries or safes")
    for name, value, low in (("poll_interval_seconds", cfg.poll_interval_seconds, 1), ("confirmations", cfg.confirmations, 0),
                             ("max_block_range", cfg.max_block_range, 1)):
        if value < low:
            raise ValueError(f"{name} must be at least {low}, not {value}")
    return cfg
