"""Watch a Safe's pending transaction queue via the Safe Transaction Service.

The point of a multisig is that the proposal is visible before it executes.
ownerwatch alerts when a new transaction is proposed, when it collects enough
signatures to be executable, and keeps the set of seen hashes in the cursor
file so restarts don't re-alert.

Service URLs follow https://api.safe.global/tx-service/<chain>/api/v1/...;
chain keys as published by Safe: eth, base, arb1, oeth, pol, gno, bnb, sep,
avax, scr, linea, mantle, celo, aurora, sonic, zksync, berachain, ink,
unichain, hemi, ...
No API key was needed at the time of writing; one can be passed anyway.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests

from .alerts import Alert, redact
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
    seeded: bool = False                                     # True once the existing queue has been recorded silently


class SafeQueueWatcher:
    CHAIN_IDS = {"eth": 1, "base": 8453, "arb1": 42161, "oeth": 10, "pol": 137, "gno": 100, "bnb": 56,
                 "sep": 11155111, "avax": 43114, "scr": 534352, "linea": 59144, "mantle": 5000,
                 "celo": 42220, "aurora": 1313161554, "sonic": 146, "zksync": 324, "berachain": 80094,
                 "ink": 57073, "unichain": 130, "hemi": 43111}

    def __init__(self, targets: list[SafeTarget], chain_name: str, api_key: str = "",
                 session: requests.Session | None = None, w3=None):
        self.targets = targets
        self.w3 = w3
        self.chain_name = chain_name
        self.session = session or requests.Session()
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.state: dict[str, SafeState] = {self._key(t): SafeState() for t in targets}
        self.last_poll_ok = False

    @staticmethod
    def _key(t: SafeTarget) -> str:
        return f"{t.chain}:{t.address}"     # the same address can be a different Safe on another chain

    # ---- persistence helpers ------------------------------------------------------
    def export_state(self) -> dict:
        return {a: {"seen": s.seen, "ready": sorted(s.ready), "seeded": s.seeded} for a, s in self.state.items()}

    def import_state(self, d: dict) -> None:
        d = d or {}
        for t in self.targets:
            s = d.get(self._key(t)) or d.get(t.address)    # state written before 0.11 is keyed by address alone
            if s:
                # state written before `seeded` existed counts as seeded: it was recorded by an earlier first run
                self.state[self._key(t)] = SafeState(seen=dict(s.get("seen", {})), ready=set(s.get("ready", [])),
                                                     seeded=bool(s.get("seeded", True)))

    # ---- polling --------------------------------------------------------------------
    def _get(self, url: str, **params) -> dict:
        import time
        last: Exception | None = None
        for attempt in range(4):
            try:
                r = self.session.get(url, params=params or None, headers=self.headers, timeout=30)
            except requests.exceptions.Timeout as e:
                last = e
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 429 and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError(f"safe service unreachable: {last}")

    def poll(self, first_run: bool = False) -> list[Alert]:
        alerts: list[Alert] = []
        ok = True
        for t in self.targets:
            try:
                alerts += self._poll_safe(t, first_run)
            except Exception as e:  # noqa: BLE001
                ok = False
                log.warning("safe queue poll failed for %s: %s", t.label, redact(e))
        self.last_poll_ok = ok
        return alerts

    def _pending(self, base: str, address: str) -> list[dict]:
        """All unexecuted transactions, following pagination (bounded)."""
        url = f"{base}/safes/{address}/multisig-transactions/"
        params = {"executed": "false", "limit": 100}
        out: list[dict] = []
        for _ in range(10):
            page = self._get(url, **params) if params else self._get(url)
            out += page.get("results", [])
            nxt = page.get("next")
            if not nxt:
                break
            url, params = nxt, None
        return out

    def _poll_safe(self, t: SafeTarget, first_run: bool) -> list[Alert]:
        base = BASE.format(chain=t.chain)
        info = self._get(f"{base}/safes/{t.address}/")
        threshold = int(info.get("threshold", 0))
        pending = self._pending(base, t.address)
        st = self.state[self._key(t)]
        first_run = first_run or not st.seeded    # a Safe new to this config is seeded silently, whatever the others did
        out: list[Alert] = []
        live = set()
        for tx in pending:
            h = tx["safeTxHash"]
            live.add(h)
            confs = len(tx.get("confirmations") or [])

            def summary() -> str:   # decoding a call costs RPC reads: only for a transaction about to alert
                data = tx.get("data") or "0x"
                call = (describe_call(data, self.CHAIN_IDS.get(t.chain), tx.get("to"), self.w3)
                        if data not in ("0x", None) else "plain value transfer")
                value_eth = int(tx.get("value") or 0) / 10**18
                return (f"nonce {tx.get('nonce')} to {tx.get('to')} value {value_eth:,.4f} calling {call}; "
                        f"{confs}/{threshold} signatures; proposed by {tx.get('proposer') or '?'}")

            if h not in st.seen:
                st.seen[h] = confs
                if not first_run:
                    out.append(Alert("high", self.chain_name, t.address, t.label, "SafeTxProposed", "Safe",
                                     "new queued transaction: " + summary(), 0, h))
            elif confs > st.seen[h]:
                st.seen[h] = confs
            if confs >= threshold and threshold > 0 and h not in st.ready:
                st.ready.add(h)
                if not first_run:
                    out.append(Alert("critical", self.chain_name, t.address, t.label, "SafeTxExecutable", "Safe",
                                     "queued transaction has enough signatures to execute: " + summary(), 0, h))
        # forget hashes that left the queue (executed or rejected) so state stays small
        for h in list(st.seen):
            if h not in live:
                st.seen.pop(h, None)
                st.ready.discard(h)
        st.seeded = True
        return out
