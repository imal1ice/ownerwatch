import json

import ownerwatch.alerts as mod
from ownerwatch.alerts import Alert, Dispatcher
from ownerwatch.config import Alerts


class Resp:
    def raise_for_status(self):
        pass


def test_every_sink_called_and_clipped(monkeypatch):
    calls = []

    def fake_post(url, json=None, data=None, headers=None, timeout=None):
        calls.append((url, json, data))
        return Resp()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    cfg = Alerts(discord_webhook="https://d", slack_webhook="https://s", telegram_bot_token="t", telegram_chat_id="c",
                 webhook_url="https://w", min_severity="high")
    d = Dispatcher(cfg)
    long = Alert("critical", "ethereum", "0x" + "11" * 20, "L", "Upgraded", "ERC-1967", "x" * 5000, 1, "0xabc")
    d.send(long)
    urls = [c[0] for c in calls]
    assert urls == ["https://d", "https://s", "https://api.telegram.org/bott/sendMessage", "https://w"]
    assert len(calls[0][1]["content"]) == 2000 and calls[0][1]["content"].endswith("…")
    assert len(calls[1][1]["text"]) == 3000
    assert len(calls[2][1]["text"]) == 4096 and calls[2][1]["chat_id"] == "c"
    assert json.loads(calls[3][2])["event"] == "Upgraded"

    calls.clear()
    d.send(Alert("medium", "ethereum", "0x" + "11" * 20, "L", "Paused", "Pausable", "m", 1, "-"))
    assert calls == []   # below min_severity


def test_one_dead_sink_does_not_block_others(monkeypatch):
    calls = []

    def fake_post(url, **kw):
        if url == "https://d":
            raise RuntimeError("boom")
        calls.append(url)
        return Resp()

    monkeypatch.setattr(mod.requests, "post", fake_post)
    d = Dispatcher(Alerts(discord_webhook="https://d", slack_webhook="https://s"))
    d.send(Alert("info", "x", "0x" + "11" * 20, "L", "E", "S", "m", 1, "-"))
    assert calls == ["https://s"]
