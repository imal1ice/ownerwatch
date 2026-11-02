from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, replace

import requests

from .config import Alerts
from .events import severity_rank

log = logging.getLogger("ownerwatch")

OUTBOX_MAX = 1000     # failed deliveries kept per chain; past this the oldest are dropped, with a warning
_URL = re.compile(r"(https?|wss?)://(?:[^/\s'\"@]+@)?([^/\s'\"?]+)[^\s'\"]*")
_REQUEST_PATH = re.compile(r"(with url: )\S+")


def redact(e: object) -> str:
    """An exception's text without URL paths: webhook, Telegram and RPC URLs carry their secret there."""
    return _REQUEST_PATH.sub(r"\1…", _URL.sub(r"\1://\2/…", str(e)))


@dataclass
class Alert:
    severity: str
    chain: str
    contract: str
    label: str
    event: str
    source: str
    message: str
    block: int
    tx_hash: str
    block_time: str = ""   # the block's timestamp (UTC, ISO), when the watcher could read it

    def text(self, limit: int = 0) -> str:
        """Clipping shortens the message only: the block and transaction always make it through."""
        head = f"[{self.severity.upper()}] {self.label} ({self.contract}) on {self.chain}\n{self.source}.{self.event}: "
        tail = f"\nblock {self.block} tx {self.tx_hash}"
        msg = self.message
        if limit and len(head) + len(msg) + len(tail) > limit:
            msg = msg[:max(limit - len(head) - len(tail) - 1, 0)] + "…"
        return head + msg + tail


class HeartbeatGate:
    """One dead-man's-switch URL shared by several chains. Pings only once every chain has finished a healthy
    poll since the last ping, so one dead chain silences the URL instead of hiding behind the live ones."""

    def __init__(self, chains: set[str]):
        self.chains = set(chains)
        self.ok: set[str] = set()
        self.lock = threading.Lock()

    def ready(self, chain: str) -> bool:
        with self.lock:
            self.ok.add(chain)
            if self.ok >= self.chains:
                self.ok.clear()
                return True
            return False


class Dispatcher:
    """Fan an Alert out to every configured sink. Never raises: a dead webhook must not stop the poller.
    A failed delivery goes to the outbox and is retried on every poll, oldest first, until the sink takes it."""

    def __init__(self, cfg: Alerts, sinks: list | None = None):
        self.cfg = cfg
        self.min_rank = severity_rank(cfg.min_severity)
        self.extra_sinks = sinks or []  # callables, used by tests
        self.counts: dict[str, int] = {}   # severity -> alerts sent today
        self.digest_day: str | None = None
        self.outbox: list[dict] = []       # {"sink": name, "alert": asdict(alert)}
        self.heartbeat_gate: HeartbeatGate | None = None

    def _sinks(self) -> dict:
        return {"discord": self._discord, "slack": self._slack, "telegram": self._telegram,
                "webhook": self._webhook, "jsonl": self._jsonl}

    @staticmethod
    def _print(text: str) -> None:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(enc, "backslashreplace").decode(enc), file=sys.stdout, flush=True)

    def send(self, alert: Alert, force: bool = False) -> bool:
        """True when every sink took it. `force` skips min_severity: digests and test alerts must arrive."""
        self._print(alert.text())
        self.counts[alert.severity] = self.counts.get(alert.severity, 0) + 1
        if not force and severity_rank(alert.severity) < self.min_rank:
            return True
        for fn in self.extra_sinks:
            fn(alert)
        ok = True
        queued = {item["sink"] for item in self.outbox}
        for name, fn in self._sinks().items():
            if name in queued:   # keep this sink's alerts in order behind the ones waiting
                self._queue(name, alert)
                ok = False
                continue
            try:
                fn(alert, alert.text())
            except Exception as e:  # noqa: BLE001
                log.warning("%s delivery failed, will retry: %s", name, redact(e))
                self._queue(name, alert)
                ok = False
        return ok

    def _queue(self, name: str, alert: Alert) -> None:
        self.outbox.append({"sink": name, "alert": asdict(alert)})
        if len(self.outbox) > OUTBOX_MAX:
            lost = self.outbox.pop(0)
            log.error("outbox full: dropped a %s alert for %s", lost["sink"], lost["alert"].get("event"))

    @staticmethod
    def _unsendable(e: Exception) -> bool:
        """The sink rejected this payload itself. Retrying cannot help, and it would block everything behind it."""
        return isinstance(e, requests.HTTPError) and e.response is not None and e.response.status_code in (400, 413, 422)

    def flush(self) -> None:
        """Retry the outbox. A sink that still fails keeps its place until the next poll."""
        failed: set[str] = set()
        keep: list[dict] = []
        for item in self.outbox:
            name = item["sink"]
            if name in failed:
                keep.append(item)
                continue
            try:
                alert = Alert(**item["alert"])
                self._sinks()[name](alert, alert.text())
            except Exception as e:  # noqa: BLE001
                if self._unsendable(e):
                    log.error("%s rejected an alert for %s, dropping it: %s", name, item["alert"].get("event"), redact(e))
                    continue
                log.warning("%s retry failed: %s", name, redact(e))
                failed.add(name)
                keep.append(item)
        self.outbox = keep

    def maybe_digest(self, chain: str, head: int, today: str | None = None) -> bool:
        """At the first poll of each UTC day, post yesterday's summary. Returns True when sent."""
        import datetime as _dt
        today = today or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        if not self.cfg.daily_digest:
            return False
        if self.digest_day is None:
            self.digest_day = today
            return False
        if today == self.digest_day:
            return False
        summary = ", ".join(f"{k}: {self.counts.get(k, 0)}" for k in ("critical", "high", "medium", "info"))
        self.send(Alert("info", chain, "-", "ownerwatch", "DailyDigest", "ownerwatch",
                        f"digest for {self.digest_day}: {summary}; watcher alive, head block {head}", head, "-"), force=True)
        self.counts = {}
        self.digest_day = today
        return True

    def heartbeat(self, chain: str = "") -> None:
        """Ping the dead-man's-switch URL. Silence there means the watcher is down."""
        if not self.cfg.heartbeat_url:
            return
        if self.heartbeat_gate and not self.heartbeat_gate.ready(chain):
            return
        try:
            requests.get(self.cfg.heartbeat_url, timeout=10)
        except Exception as e:  # noqa: BLE001
            log.warning("heartbeat failed: %s", redact(e))

    @staticmethod
    def _clip(text: str, limit: int) -> str:
        return text if len(text) <= limit else text[: limit - 1] + "…"

    @staticmethod
    def _post(url: str, **kw) -> None:
        """POST, waiting out a 429 for what the sink asks: a burst of alerts must not lose the tail of the burst."""
        for attempt in range(3):
            r = requests.post(url, timeout=10, **kw)
            if r.status_code != 429 or attempt == 2:
                break
            try:
                wait = float(r.headers.get("Retry-After", ""))
            except ValueError:
                wait = 2.0 ** attempt
            time.sleep(min(wait, 30))
        r.raise_for_status()

    COLORS = {"info": 0x95A5A6, "medium": 0xF1C40F, "high": 0xE67E22, "critical": 0xE74C3C}

    def _discord(self, alert: Alert, text: str) -> None:
        if self.cfg.discord_webhook:
            embed = {
                "title": self._clip(f"[{alert.severity.upper()}] {alert.label}: {alert.source}.{alert.event}", 256),
                "description": self._clip(alert.message, 4096),
                "color": self.COLORS.get(alert.severity, 0x95A5A6),
                "fields": [
                    {"name": "Contract", "value": f"`{alert.contract}`", "inline": True},
                    {"name": "Chain", "value": alert.chain, "inline": True},
                    {"name": "Block", "value": str(alert.block), "inline": True},
                    {"name": "Tx", "value": self._clip(alert.tx_hash, 1024), "inline": False},
                ],
            }
            self._post(self.cfg.discord_webhook, json={"embeds": [embed]})

    def _slack(self, alert: Alert, text: str) -> None:
        if self.cfg.slack_webhook:
            # on-chain text must not turn into Slack links or mentions
            esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            self._post(self.cfg.slack_webhook, json={"text": replace(alert, message=esc(alert.message), label=esc(alert.label)).text(3000)})

    def _telegram(self, alert: Alert, text: str) -> None:
        if self.cfg.telegram_bot_token and self.cfg.telegram_chat_id:
            self._post(f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage",
                       json={"chat_id": self.cfg.telegram_chat_id, "text": alert.text(4096), "disable_web_page_preview": True})

    def _jsonl(self, alert: Alert, text: str) -> None:
        if self.cfg.jsonl_path:
            import datetime as _dt
            import os
            os.makedirs(os.path.dirname(self.cfg.jsonl_path) or ".", exist_ok=True)
            row = {"ts": alert.block_time or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **asdict(alert)}
            with open(self.cfg.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _webhook(self, alert: Alert, text: str) -> None:
        if self.cfg.webhook_url:
            self._post(self.cfg.webhook_url, data=json.dumps(asdict(alert)), headers={"content-type": "application/json"})
