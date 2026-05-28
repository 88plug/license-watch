"""Exponential-backoff retry wrapper for Apprise sends.

Wraps every notification attempt with tenacity. Failures after the final
attempt are dead-lettered to a JSONL file and (optionally) uploaded to an
R2 bucket so we can replay them later.

Backoff: 2^n seconds (2, 4, 8, 16, 32) capped at `max_attempts`.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from tenacity import (
    RetryError,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

log = logging.getLogger("license_watch.notify.retry")


class NotifyError(Exception):
    """Raised when an Apprise send returns False (no exception, but failed)."""


@dataclass
class DeadLetter:
    ts: str
    channel_group: str  # "alerts" | "heartbeat"
    title: str
    body: str
    error: str
    attempts: int


def send_with_retry(
    send_callable: Callable[[], bool],
    *,
    channel_group: str,
    title: str,
    body: str,
    max_attempts: int = 5,
    base_backoff: float = 2.0,
    dead_letter_path: str | os.PathLike[str] = "failed_alerts.jsonl",
    r2_uploader: Callable[[bytes, str], None] | None = None,
) -> bool:
    """Invoke ``send_callable`` with exponential backoff.

    ``send_callable`` should perform a single Apprise notify and return
    True on success or False/raise on failure.

    Returns True if any attempt succeeded; False after exhausting retries.
    On exhaustion, a JSONL line is appended to ``dead_letter_path`` and
    (if ``r2_uploader`` is provided) uploaded to R2.
    """
    attempts = 0
    last_err: Exception | None = None
    try:
        for attempt in Retrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=base_backoff, max=base_backoff ** max_attempts),
            retry=retry_if_exception_type((NotifyError, Exception)),
            reraise=True,
        ):
            with attempt:
                attempts = attempt.retry_state.attempt_number
                ok = send_callable()
                if not ok:
                    raise NotifyError(f"send returned False on attempt {attempts}")
        return True
    except (RetryError, Exception) as e:  # noqa: BLE001 — we re-package below
        last_err = e
        log.error("notify exhausted after %d attempts: %s", attempts, e)

    # Dead-letter path.
    dl = DeadLetter(
        ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        channel_group=channel_group,
        title=title,
        body=body,
        error=str(last_err) if last_err else "unknown",
        attempts=attempts or max_attempts,
    )
    _append_dead_letter(dead_letter_path, dl)
    if r2_uploader is not None:
        try:
            key = f"alerts/{dl.ts}-{channel_group}.json"
            r2_uploader(json.dumps(asdict(dl)).encode("utf-8"), key)
        except Exception as up_err:  # noqa: BLE001 — uploader is best-effort
            log.warning("R2 upload of dead-letter failed: %s", up_err)
    return False


def _append_dead_letter(path: str | os.PathLike[str], dl: DeadLetter) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(dl)) + "\n")


def read_dead_letters(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out
