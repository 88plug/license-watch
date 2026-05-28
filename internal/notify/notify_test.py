"""Unit tests for L8 notification fanout.

Runs WITHOUT live notification services — Apprise instances are stubbed
to assert URL parsing, env interpolation, retry, and dead-letter paths.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

import internal.notify.notify as notify_mod
from internal.notify.notify import (
    _drop_empty_urls,
    interpolate,
    load_config,
    send,
)
from internal.notify.retry import (
    NotifyError,
    read_dead_letters,
    send_with_retry,
)


# ---------- env interpolation ----------

def test_interpolate_basic():
    assert interpolate("hello ${NAME}", {"NAME": "world"}) == "hello world"


def test_interpolate_default():
    assert (
        interpolate("${MISSING:-fallback-value}", {})
        == "fallback-value"
    )


def test_interpolate_missing_no_default_becomes_empty():
    assert interpolate("x=${MISSING}", {}) == "x="


def test_interpolate_preserves_non_placeholders():
    s = "ntfys://user:pass@example.com/topic?key=val"
    assert interpolate(s, {}) == s


# ---------- config loading ----------

def test_load_config_resolves_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = tmp_path / "n.yml"
    cfg.write_text(
        "alerts:\n"
        "  title_prefix: '[lw]'\n"
        "  urls:\n"
        "    - '${MY_NTFY:-ntfys://example.com/default-topic}'\n"
        "    - '${ALSO_SET}'\n"
        "retry: {max_attempts: 3, base_backoff_seconds: 1}\n"
        "dead_letter: {jsonl_path: failed.jsonl}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ALSO_SET", "discord://x/y")
    monkeypatch.delenv("MY_NTFY", raising=False)
    loaded = load_config(cfg)
    assert loaded["alerts"]["urls"][0] == "ntfys://example.com/default-topic"
    assert loaded["alerts"]["urls"][1] == "discord://x/y"
    assert loaded["retry"]["max_attempts"] == 3


def test_drop_empty_urls():
    assert _drop_empty_urls(["ntfys://a", "", "${UNRESOLVED}", "discord://x"]) == [
        "ntfys://a",
        "discord://x",
    ]


# ---------- retry / dead-letter ----------

def test_retry_succeeds_first_try(tmp_path: Path):
    calls = {"n": 0}

    def ok() -> bool:
        calls["n"] += 1
        return True

    dl = tmp_path / "dl.jsonl"
    assert (
        send_with_retry(
            ok,
            channel_group="alerts",
            title="t",
            body="b",
            max_attempts=3,
            base_backoff=0.0,
            dead_letter_path=dl,
        )
        is True
    )
    assert calls["n"] == 1
    assert not dl.exists() or dl.read_text() == ""


def test_retry_recovers_after_failures(tmp_path: Path):
    calls = {"n": 0}

    def flaky() -> bool:
        calls["n"] += 1
        return calls["n"] >= 3  # fail twice, succeed third

    dl = tmp_path / "dl.jsonl"
    ok = send_with_retry(
        flaky,
        channel_group="alerts",
        title="t",
        body="b",
        max_attempts=5,
        base_backoff=0.0,
        dead_letter_path=dl,
    )
    assert ok is True
    assert calls["n"] == 3
    assert not dl.exists() or dl.read_text() == ""


def test_retry_exhausts_and_dead_letters(tmp_path: Path):
    def always_fail() -> bool:
        raise NotifyError("boom")

    dl = tmp_path / "dl.jsonl"
    ok = send_with_retry(
        always_fail,
        channel_group="alerts",
        title="title",
        body="body",
        max_attempts=3,
        base_backoff=0.0,
        dead_letter_path=dl,
    )
    assert ok is False
    assert dl.exists()
    rows = read_dead_letters(dl)
    assert len(rows) == 1
    row = rows[0]
    assert row["channel_group"] == "alerts"
    assert row["title"] == "title"
    assert row["body"] == "body"
    assert row["attempts"] == 3
    assert "boom" in row["error"]


# ---------- end-to-end send (with stubbed Apprise) ----------

class _FakeApprise:
    def __init__(self, *, ok: bool = True):
        self._ok = ok
        self.added: list[str] = []
        self.calls: list[tuple[str, str]] = []

    def add(self, url: str) -> bool:
        self.added.append(url)
        return True

    def notify(self, *, title: str, body: str) -> bool:
        self.calls.append((title, body))
        return self._ok


def test_send_invokes_apprise_with_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = {
        "alerts": {
            "title_prefix": "[lw]",
            "urls": ["ntfys://example.com/topic"],
        },
        "retry": {"max_attempts": 1, "base_backoff_seconds": 0},
        "dead_letter": {"jsonl_path": str(tmp_path / "dl.jsonl")},
    }
    fake = _FakeApprise(ok=True)
    with mock.patch.object(notify_mod, "build_apprise", return_value=fake):
        ok = send(cfg, channel_group="alerts", title="hi", body="there")
    assert ok is True
    assert fake.calls == [("[lw] hi", "there")]


def test_send_returns_false_when_no_urls(tmp_path: Path):
    cfg = {
        "alerts": {"urls": ["${MISSING}"]},
        "retry": {"max_attempts": 1, "base_backoff_seconds": 0},
        "dead_letter": {"jsonl_path": str(tmp_path / "dl.jsonl")},
    }
    assert send(cfg, channel_group="alerts", title="t", body="b") is False


def test_send_dead_letters_when_apprise_fails(tmp_path: Path):
    cfg = {
        "alerts": {
            "title_prefix": "[lw]",
            "urls": ["ntfys://example.com/topic"],
        },
        "retry": {"max_attempts": 2, "base_backoff_seconds": 0},
        "dead_letter": {"jsonl_path": str(tmp_path / "dl.jsonl")},
    }
    fake = _FakeApprise(ok=False)
    with mock.patch.object(notify_mod, "build_apprise", return_value=fake):
        ok = send(cfg, channel_group="alerts", title="hi", body="body")
    assert ok is False
    rows = read_dead_letters(tmp_path / "dl.jsonl")
    assert len(rows) == 1
    assert rows[0]["title"] == "[lw] hi"


# ---------- heartbeat ----------

def test_heartbeat_uses_state_when_available(tmp_path: Path):
    from internal.notify.heartbeat import latest_scan_summary

    state = tmp_path / "state.json"
    state.write_text(
        json.dumps({"last_scan_iso": "2026-05-27T11:00:00Z", "candidates_seen": 7}),
        encoding="utf-8",
    )
    iso, n = latest_scan_summary(state)
    assert iso == "2026-05-27T11:00:00Z"
    assert n == 7


def test_heartbeat_handles_missing_state(tmp_path: Path):
    from internal.notify.heartbeat import latest_scan_summary

    iso, n = latest_scan_summary(tmp_path / "missing.json")
    assert iso == "unknown"
    assert n == 0


def test_heartbeat_handles_corrupt_state(tmp_path: Path):
    from internal.notify.heartbeat import latest_scan_summary

    p = tmp_path / "state.json"
    p.write_text("not json at all", encoding="utf-8")
    iso, n = latest_scan_summary(p)
    assert iso == "unknown"
    assert n == 0
