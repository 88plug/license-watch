"""L8 — notification fanout.

Wraps Apprise (https://github.com/caronc/apprise) and a tenacity retry
loop. Reads `notify.yml` for channel URLs; environment variables are
interpolated with ``${VAR}`` or ``${VAR:-default}`` syntax so secrets
stay out of the repository.

Usage:

    python -m internal.notify.notify alert \
        --title "[severity:high] DMCA draft cand-001" \
        --body  "see https://github.com/88plug/license-watch/issues/3"

    python -m internal.notify.notify heartbeat \
        --candidates-seen 4 --last-scan-iso 2026-05-27T11:00:00Z
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    import apprise  # type: ignore[import-not-found]
except Exception as exc:  # pragma: no cover — install path
    apprise = None  # type: ignore[assignment]
    _APPRISE_ERR: Exception | None = exc
else:
    _APPRISE_ERR = None

from .retry import send_with_retry

log = logging.getLogger("license_watch.notify")
logging.basicConfig(level=os.getenv("LICENSE_WATCH_LOG_LEVEL", "INFO"))

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-(.*?))?\}")


def interpolate(text: str, env: dict[str, str] | None = None) -> str:
    """Replace ``${VAR}`` / ``${VAR:-default}`` placeholders from env."""
    env = env if env is not None else dict(os.environ)

    def repl(m: re.Match[str]) -> str:
        var, default = m.group(1), m.group(2)
        return env.get(var, default if default is not None else "")

    return _ENV_RE.sub(repl, text)


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load notify.yml and interpolate ${ENV} placeholders in every string."""
    raw = Path(path).read_text(encoding="utf-8")
    cfg = yaml.safe_load(raw) or {}
    return _interpolate_tree(cfg)


def _interpolate_tree(node: Any) -> Any:
    if isinstance(node, str):
        return interpolate(node)
    if isinstance(node, dict):
        return {k: _interpolate_tree(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_interpolate_tree(v) for v in node]
    return node


def _drop_empty_urls(urls: list[str]) -> list[str]:
    """An unresolved ${SECRET} that had no value becomes an empty string after
    interpolation — drop those before handing to Apprise."""
    return [u for u in urls if u and not u.startswith("${")]


def build_apprise(urls: list[str]):
    """Build an Apprise instance from a list of fully-formed Apprise URLs."""
    if apprise is None:  # pragma: no cover — install path
        raise RuntimeError(f"apprise not installed: {_APPRISE_ERR}")
    obj = apprise.Apprise()
    for u in urls:
        if not obj.add(u):
            log.warning("apprise rejected URL: %s", u)
    return obj


def send(
    cfg: dict[str, Any],
    *,
    channel_group: str,
    title: str,
    body: str,
) -> bool:
    """Send a notification using the channel group from notify.yml.

    Returns True on success (at least one attempt succeeded), False if all
    retries exhausted (a dead-letter row was written).
    """
    group_cfg = cfg.get(channel_group) or {}
    urls = _drop_empty_urls(list(group_cfg.get("urls") or []))
    if not urls:
        log.warning("no URLs configured for channel_group=%s", channel_group)
        return False

    prefix = group_cfg.get("title_prefix") or ""
    final_title = f"{prefix} {title}".strip() if prefix else title

    retry_cfg = cfg.get("retry") or {}
    max_attempts = int(retry_cfg.get("max_attempts", 5))
    base_backoff = float(retry_cfg.get("base_backoff_seconds", 2))

    dl_cfg = cfg.get("dead_letter") or {}
    dl_path = dl_cfg.get("jsonl_path", "failed_alerts.jsonl")

    appr = build_apprise(urls)

    def _do_send() -> bool:
        # Apprise returns True if ALL configured services succeeded; we treat
        # partial success as success (some channels may be down).
        return bool(appr.notify(title=final_title, body=body))

    return send_with_retry(
        _do_send,
        channel_group=channel_group,
        title=final_title,
        body=body,
        max_attempts=max_attempts,
        base_backoff=base_backoff,
        dead_letter_path=dl_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="license-watch-notify")
    parser.add_argument("--config", default="internal/notify/notify.yml")
    sub = parser.add_subparsers(dest="cmd", required=True)

    alert = sub.add_parser("alert", help="send an alert notification")
    alert.add_argument("--title", required=True)
    alert.add_argument("--body", required=True)

    hb = sub.add_parser("heartbeat", help="send a daily/weekly heartbeat")
    hb.add_argument("--candidates-seen", type=int, default=0)
    hb.add_argument("--last-scan-iso", default="unknown")

    args = parser.parse_args(argv)
    cfg = load_config(args.config)

    if args.cmd == "alert":
        ok = send(cfg, channel_group="alerts", title=args.title, body=args.body)
    elif args.cmd == "heartbeat":
        body = (
            "watcher alive\n"
            f"last scan: {args.last_scan_iso}\n"
            f"candidates seen: {args.candidates_seen}"
        )
        ok = send(cfg, channel_group="heartbeat", title="watcher alive", body=body)
    else:  # pragma: no cover — argparse handles
        parser.error(f"unknown command {args.cmd}")
        return 2
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
