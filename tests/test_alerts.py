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
    embed = calls[0][1]["embeds"][0]
    assert embed["color"] == 0xE74C3C and len(embed["description"]) == 4096 and embed["title"].startswith("[CRITICAL] L: ERC-1967.Upgraded")
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


def test_heartbeat_only_when_configured(monkeypatch):
    gets = []
    monkeypatch.setattr(mod.requests, "get", lambda url, timeout=None: gets.append(url))
    Dispatcher(Alerts()).heartbeat()
    assert gets == []
    Dispatcher(Alerts(heartbeat_url="https://hc/ping")).heartbeat()
    assert gets == ["https://hc/ping"]


def test_daily_digest_fires_once_per_day_change():
    got = []
    d = Dispatcher(Alerts(daily_digest=True), sinks=[got.append])
    assert d.maybe_digest("ethereum", 100, today="2026-10-14") is False     # first poll just records the day
    d.send(Alert("critical", "ethereum", "0x" + "11" * 20, "L", "Upgraded", "ERC-1967", "m", 1, "-"))
    assert d.maybe_digest("ethereum", 200, today="2026-10-14") is False     # same day, nothing
    assert d.maybe_digest("ethereum", 300, today="2026-10-15") is True
    digest = got[-1]
    assert digest.event == "DailyDigest" and "critical: 1" in digest.message and "2026-10-14" in digest.message
    assert d.counts == {} and d.maybe_digest("ethereum", 400, today="2026-10-15") is False
    assert Dispatcher(Alerts()).maybe_digest("x", 1, today="2026-10-15") is False   # off by default


def test_jsonl_sink_appends_one_line_per_alert(tmp_path):
    import json
    path = tmp_path / "out" / "alerts.jsonl"
    d = Dispatcher(Alerts(jsonl_path=str(path)))
    d.send(Alert("high", "ethereum", "0xabc", "Timelock", "CallScheduled", "timelock", "queued x", 1, "0xtx"))
    d.send(Alert("info", "base", "0xdef", "Safe", "AddedOwner", "safe", "owner added", 2, "0xtx2"))
    rows = [json.loads(l) for l in path.read_text().splitlines()]
    assert [r["event"] for r in rows] == ["CallScheduled", "AddedOwner"]
    assert rows[0]["severity"] == "high" and rows[0]["block"] == 1 and rows[0]["ts"].endswith("Z")
