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
class Alerts:
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    min_severity: str = "info"


@dataclass
class Config:
    rpc_url: str
    chain_name: str = "ethereum"
    poll_interval_seconds: int = 15
    confirmations: int = 2
    max_block_range: int = 2000
    start_block: int | str = "latest"
    state_file: str = "state/cursor.json"
    contracts: list[Contract] = field(default_factory=list)
    treasuries: list[Treasury] = field(default_factory=list)
    alerts: Alerts = field(default_factory=Alerts)

    def labels(self) -> dict[str, str]:
        out = {c.address: c.label for c in self.contracts}
        out.update({t.address: t.label for t in self.treasuries})
        return out


def _addr(a: str) -> str:
    return Web3.to_checksum_address(a)


def load(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    contracts = [Contract(_addr(c["address"]), c.get("label", c["address"])) for c in raw.get("contracts", []) or []]
    treasuries = []
    for t in raw.get("treasuries", []) or []:
        tokens = [Token(_addr(k["address"]), k.get("symbol", "?"), int(k.get("decimals", 18)), float(k.get("min_amount", 0)))
                  for k in t.get("tokens", []) or []]
        nfts = [Collection(_addr(n["address"]), n.get("label", n["address"])) for n in t.get("nfts", []) or []]
        drop = t.get("min_native_drop")
        treasuries.append(Treasury(_addr(t["address"]), t.get("label", t["address"]), tokens, nfts,
                                   float(drop) if drop is not None else None))
    alerts = Alerts(**{k: v for k, v in (raw.get("alerts") or {}).items() if k in Alerts.__dataclass_fields__})
    cfg = Config(
        rpc_url=raw["rpc_url"],
        chain_name=raw.get("chain_name", "ethereum"),
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 15)),
        confirmations=int(raw.get("confirmations", 2)),
        max_block_range=int(raw.get("max_block_range", 2000)),
        start_block=raw.get("start_block", "latest"),
        state_file=raw.get("state_file", "state/cursor.json"),
        contracts=contracts,
        treasuries=treasuries,
        alerts=alerts,
    )
    if not cfg.contracts and not cfg.treasuries:
        raise ValueError("config has nothing to watch: add contracts or treasuries")
    return cfg
