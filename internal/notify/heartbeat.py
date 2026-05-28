"""Heartbeat helper.

Fires a heartbeat notification regardless of pipeline activity. If the
pipeline has stalled, this is the canary that tells you so.

Run from `.github/workflows/heartbeat.yml` on a weekly cron.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from .notify import load_config, send


def latest_scan_summary(state_path: str | os.PathLike[str]) -> tuple[str, int]:
    """Return (last_scan_iso, candidates_seen_last_window).

    Reads a small ``state.json`` file written by L1/L2 if present; falls
    back to "unknown" + 0 so a missing state file does NOT silence the
    heartbeat (silence is the failure mode we are guarding against).
    """
    p = Path(state_path)
    if not p.exists():
        return ("unknown", 0)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return (
            str(data.get("last_scan_iso") or "unknown"),
            int(data.get("candidates_seen") or 0),
        )
    except Exception:  # noqa: BLE001 — heartbeat must never crash
        return ("unknown", 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="license-watch-heartbeat")
    parser.add_argument("--config", default="internal/notify/notify.yml")
    parser.add_argument("--state", default="state.json")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    last_iso, seen = latest_scan_summary(args.state)
    now_iso = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = (
        "license-watch heartbeat\n"
        f"now: {now_iso}\n"
        f"last scan: {last_iso}\n"
        f"candidates seen (last window): {seen}\n"
        "If you stop seeing this weekly, the pipeline is silently down."
    )
    ok = send(cfg, channel_group="heartbeat", title="watcher alive", body=body)
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
