"""Watch a Safe's pending transaction queue via the Safe Transaction Service.

The point of a multisig is that the proposal is visible before it executes.
ownerwatch alerts when a new transaction is proposed, when it collects enough
signatures to be executable, and keeps the set of seen hashes in the cursor
file so restarts don't re-alert.

Service URLs follow https://api.safe.global/tx-service/<chain>/api/v1/...;
chain keys as published by Safe: eth, base, arb1, oeth, matic, gno, bnb,
sep, avax, scr, linea, zkevm, mantle, blast, celo, aurora, xlayer, sonic, ...
No API key was needed at the time of writing; one can be passed anyway.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests

from .alerts import Alert
from .decode import describe_call

log = logging.getLogger("ownerwatch")
BASE = "https://api.safe.global/tx-service/{chain}/api/v1"


@dataclass
class SafeTarget:
    address: str
    label: str
    chain: str = "eth"


@dataclass
class SafeState:
    seen: dict[str, int] = field(default_factory=dict)       # safeTxHash -> confirmations seen
    ready: set[str] = field(default_factory=set)             # hashes already reported as executable


class SafeQueueWatcher:
    CHAIN_IDS = {"eth": 1, "base": 8453, "arb1": 42161, "oeth": 10, "matic": 137, "gno": 100, "bnb": 56,
                 "sep": 11155111, "avax": 43114, "scr": 534352, "linea": 59144, "zkevm": 1101, "mantle": 5000,
                 "blast": 81457, "celo": 42220, "sonic": 146}

    def __init__(self, targets: list[SafeTarget], chain_name: str, api_key: str = "",
                 session: requests.Session | None = None):
        self.targets = targets
        self.chain_name = chain_name
        self.session = session or requests.Session()
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.state: dict[str, SafeState] = {t.address: SafeState() for t in targets}

    # ---- persistence helpers ------------------------------------------------------
    def export_state(self) -> dict:
        return {a: {"seen": s.seen, "ready": sorted(s.ready)} for a, s in self.state.items()}

    def import_state(self, d: dict) -> None:
        for a, s in (d or {}).items():
            if a in self.state:
                self.state[a] = SafeState(seen=dict(s.get("seen", {})), ready=set(s.get("ready", [])))

    # ---- polling --------------------------------------------------------------------
    def _get(self, url: str, **params) -> dict:
        import time
        for attempt in range(4):
            r = self.session.get(url, params=params, headers=self.headers, timeout=15)
            if r.status_code == 429 and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def poll(self, first_run: bool = False) -> list[Alert]:
        alerts: list[Alert] = []
        for t in self.targets:
            try:
                alerts += self._poll_safe(t, first_run)
            except Exception as e:  # noqa: BLE001
                log.warning("safe queue poll failed for %s: %s", t.label, e)
        return alerts

    def _poll_safe(self, t: SafeTarget, first_run: bool) -> list[Alert]:
        base = BASE.format(chain=t.chain)
        info = self._get(f"{base}/safes/{t.address}/")
        threshold = int(info.get("threshold", 0))
        pending = self._get(f"{base}/safes/{t.address}/multisig-transactions/", executed="false", limit=50)
        st = self.state[t.address]
        out: list[Alert] = []
        live = set()
        for tx in pending.get("results", []):
            h = tx["safeTxHash"]
            live.add(h)
            confs = len(tx.get("confirmations") or [])
            data = tx.get("data") or "0x"
            call = (describe_call(data, self.CHAIN_IDS.get(t.chain), tx.get("to"))
                    if data not in ("0x", None) else "plain value transfer")
            value_eth = int(tx.get("value") or 0) / 10**18
            summary = (f"nonce {tx.get('nonce')} to {tx.get('to')} value {value_eth:,.4f} calling {call}; "
                       f"{confs}/{threshold} signatures; proposed by {tx.get('proposer') or '?'}")
            if h not in st.seen:
                st.seen[h] = confs
                if not first_run:
                    out.append(Alert("high", self.chain_name, t.address, t.label, "SafeTxProposed", "Safe",
                                     "new queued transaction: " + summary, 0, h))
            elif confs > st.seen[h]:
                st.seen[h] = confs
            if confs >= threshold and threshold > 0 and h not in st.ready:
                st.ready.add(h)
                if not first_run:
                    out.append(Alert("critical", self.chain_name, t.address, t.label, "SafeTxExecutable", "Safe",
                                     "queued transaction has enough signatures to execute: " + summary, 0, h))
        # forget hashes that left the queue (executed or rejected) so state stays small
        for h in list(st.seen):
            if h not in live:
                st.seen.pop(h, None)
                st.ready.discard(h)
        return out
