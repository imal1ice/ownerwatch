from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from web3 import Web3


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

    def labels(self) -> dict[str, str]:
        out = {c.address: c.label for c in self.contracts}
        out.update({t.address: t.label for t in self.treasuries})
        out.update({s.address: s.label for s in self.safes})
        return out


def _addr(a: str) -> str:
    return Web3.to_checksum_address(a)


SHARED_KEYS = ("explorer_url", "poll_interval_seconds", "confirmations", "max_block_range", "start_block", "alerts", "safe_api_key")
CHAIN_KEYS = {"rpc_url", "chain_name", "probe_rpc_url", "state_file", "contracts", "treasuries", "safes", *SHARED_KEYS}
SEVERITY_LEVELS = ("info", "medium", "high", "critical")
# Safe Transaction Service key for a chain_name, so a Safe on a Base config does not default to Ethereum's service.
SAFE_CHAIN_KEYS = {"ethereum": "eth", "mainnet": "eth", "base": "base", "arbitrum": "arb1", "optimism": "oeth", "polygon": "pol",
                   "gnosis": "gno", "bsc": "bnb", "bnb": "bnb", "sepolia": "sep", "avalanche": "avax", "scroll": "scr",
                   "linea": "linea", "mantle": "mantle", "celo": "celo", "aurora": "aurora", "sonic": "sonic",
                   "zksync": "zksync", "berachain": "berachain", "ink": "ink", "unichain": "unichain", "hemi": "hemi"}
SAFE_KEY_ALIASES = {"matic": "pol"}   # the service renamed it; the old key answers 404


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
    )
    if not cfg.contracts and not cfg.treasuries and not cfg.safes:
        raise ValueError("config has nothing to watch: add contracts, treasuries or safes")
    for name, value, low in (("poll_interval_seconds", cfg.poll_interval_seconds, 1), ("confirmations", cfg.confirmations, 0),
                             ("max_block_range", cfg.max_block_range, 1)):
        if value < low:
            raise ValueError(f"{name} must be at least {low}, not {value}")
    return cfg
