from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from web3 import Web3


@dataclass
class Token:
    address: str
    symbol: str
    decimals: int
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
    min_severity: str = "info"


@dataclass
class Config:
    rpc_url: str
    chain_name: str = "ethereum"
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


def load_all(path: str | Path) -> list[Config]:
    """One Config per chain. A file with a top-level `chains:` list yields one
    Config per entry; keys in SHARED_KEYS are inherited from the top level."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if "chains" not in raw:
        return [_build(raw)]
    out = []
    for entry in raw["chains"] or []:
        merged = {k: raw[k] for k in SHARED_KEYS if k in raw}
        merged.update(entry)
        merged.setdefault("state_file", f"state/{merged.get('chain_name', 'chain')}.json")
        out.append(_build(merged))
    if not out:
        raise ValueError("chains: is empty")
    return out


def load(path: str | Path) -> Config:
    cfgs = load_all(path)
    if len(cfgs) > 1:
        raise ValueError("multi-chain config: use load_all()")
    return cfgs[0]


def _build(raw: dict) -> Config:
    contracts = [Contract(_addr(c["address"]), c.get("label", c["address"])) for c in raw.get("contracts", []) or []]
    treasuries = []
    for t in raw.get("treasuries", []) or []:
        tokens = [Token(_addr(k["address"]), k.get("symbol", "?"), int(k.get("decimals", 18)), float(k.get("min_amount", 0)))
                  for k in t.get("tokens", []) or []]
        nfts = [Collection(_addr(n["address"]), n.get("label", n["address"])) for n in t.get("nfts", []) or []]
        drop = t.get("min_native_drop")
        treasuries.append(Treasury(_addr(t["address"]), t.get("label", t["address"]), tokens, nfts,
                                   float(drop) if drop is not None else None))
    safes = [Safe(_addr(x["address"]), x.get("label", x["address"]), x.get("chain", "eth")) for x in raw.get("safes", []) or []]
    alerts = Alerts(**{k: v for k, v in (raw.get("alerts") or {}).items() if k in Alerts.__dataclass_fields__})
    cfg = Config(
        rpc_url=raw["rpc_url"],
        chain_name=raw.get("chain_name", "ethereum"),
        explorer_url=str(raw.get("explorer_url", "") or ""),
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 15)),
        confirmations=int(raw.get("confirmations", 2)),
        max_block_range=int(raw.get("max_block_range", 2000)),
        start_block=raw.get("start_block", "latest"),
        state_file=raw.get("state_file", "state/cursor.json"),
        contracts=contracts,
        treasuries=treasuries,
        safes=safes,
        safe_api_key=str(raw.get("safe_api_key", "") or ""),
        alerts=alerts,
    )
    if not cfg.contracts and not cfg.treasuries and not cfg.safes:
        raise ValueError("config has nothing to watch: add contracts or treasuries")
    return cfg
