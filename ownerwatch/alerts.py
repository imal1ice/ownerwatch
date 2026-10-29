from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass

import requests

from .config import Alerts
from .events import severity_rank

log = logging.getLogger("ownerwatch")


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

    def text(self) -> str:
        return (f"[{self.severity.upper()}] {self.label} ({self.contract}) on {self.chain}\n"
                f"{self.source}.{self.event}: {self.message}\n"
                f"block {self.block} tx {self.tx_hash}")


class Dispatcher:
    """Fan an Alert out to every configured sink. Never raises: a dead
    webhook must not stop the poller."""

    def __init__(self, cfg: Alerts, sinks: list | None = None):
        self.cfg = cfg
        self.min_rank = severity_rank(cfg.min_severity)
        self.extra_sinks = sinks or []  # callables, used by tests
        self.counts: dict[str, int] = {}   # severity -> alerts sent today
        self.digest_day: str | None = None

    def send(self, alert: Alert) -> None:
        print(alert.text(), file=sys.stdout, flush=True)
        self.counts[alert.severity] = self.counts.get(alert.severity, 0) + 1
        if severity_rank(alert.severity) < self.min_rank:
            return
        for fn in self.extra_sinks:
            fn(alert)
        text = alert.text()
        for name, fn in (("discord", self._discord), ("slack", self._slack), ("telegram", self._telegram), ("webhook", self._webhook), ("jsonl", self._jsonl)):
            try:
                fn(alert, text)
            except Exception as e:  # noqa: BLE001
                log.warning("%s delivery failed: %s", name, e)

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
                        f"digest for {self.digest_day}: {summary}; watcher alive, head block {head}", head, "-"))
        self.counts = {}
        self.digest_day = today
        return True

    def heartbeat(self) -> None:
        """Ping the dead-man's-switch URL. Silence there means the watcher is down."""
        if not self.cfg.heartbeat_url:
            return
        try:
            requests.get(self.cfg.heartbeat_url, timeout=10)
        except Exception as e:  # noqa: BLE001
            log.warning("heartbeat failed: %s", e)

    @staticmethod
    def _clip(text: str, limit: int) -> str:
        return text if len(text) <= limit else text[: limit - 1] + "…"

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
            requests.post(self.cfg.discord_webhook, json={"embeds": [embed]}, timeout=10).raise_for_status()

    def _slack(self, alert: Alert, text: str) -> None:
        if self.cfg.slack_webhook:
            requests.post(self.cfg.slack_webhook, json={"text": self._clip(text, 3000)}, timeout=10).raise_for_status()

    def _telegram(self, alert: Alert, text: str) -> None:
        if self.cfg.telegram_bot_token and self.cfg.telegram_chat_id:
            requests.post(f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage",
                          json={"chat_id": self.cfg.telegram_chat_id, "text": self._clip(text, 4096),
                                "disable_web_page_preview": True}, timeout=10).raise_for_status()

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
            requests.post(self.cfg.webhook_url, data=json.dumps(asdict(alert)),
                          headers={"content-type": "application/json"}, timeout=10).raise_for_status()
