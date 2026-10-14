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

    def send(self, alert: Alert) -> None:
        print(alert.text(), file=sys.stdout, flush=True)
        if severity_rank(alert.severity) < self.min_rank:
            return
        for fn in self.extra_sinks:
            fn(alert)
        text = alert.text()
        for name, fn in (("discord", self._discord), ("slack", self._slack), ("telegram", self._telegram), ("webhook", self._webhook)):
            try:
                fn(alert, text)
            except Exception as e:  # noqa: BLE001
                log.warning("%s delivery failed: %s", name, e)

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

    def _discord(self, alert: Alert, text: str) -> None:
        if self.cfg.discord_webhook:
            requests.post(self.cfg.discord_webhook, json={"content": self._clip(text, 2000)}, timeout=10).raise_for_status()

    def _slack(self, alert: Alert, text: str) -> None:
        if self.cfg.slack_webhook:
            requests.post(self.cfg.slack_webhook, json={"text": self._clip(text, 3000)}, timeout=10).raise_for_status()

    def _telegram(self, alert: Alert, text: str) -> None:
        if self.cfg.telegram_bot_token and self.cfg.telegram_chat_id:
            requests.post(f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage",
                          json={"chat_id": self.cfg.telegram_chat_id, "text": self._clip(text, 4096),
                                "disable_web_page_preview": True}, timeout=10).raise_for_status()

    def _webhook(self, alert: Alert, text: str) -> None:
        if self.cfg.webhook_url:
            requests.post(self.cfg.webhook_url, data=json.dumps(asdict(alert)),
                          headers={"content-type": "application/json"}, timeout=10).raise_for_status()
