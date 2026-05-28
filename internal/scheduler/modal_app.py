"""license-watch — L1 Modal.com heavy-CPU runner.

Cloudflare Worker (worker.js) POSTs cursors here every hour. We:
  1. Pull the Go detector binary (built by GH Actions, hosted on R2 or GH releases).
  2. Pull watch.yml from the repo.
  3. Run `detect --cursors-json=... --watch=watch.yml --out=/tmp/candidates.jsonl`.
  4. Stream candidates to R2 + return new cursors to the Worker.

Modal docs: https://modal.com/docs/guide/webhooks
Free tier: 10 GPU-hr + 1000 CPU-hr per month — well under our budget.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import modal

app = modal.App("license-watch-detect")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("curl", "ca-certificates", "git")
    .pip_install("pyyaml==6.0.2", "requests==2.32.3")
)

DETECT_BIN_URL = os.environ.get(
    "DETECT_BIN_URL",
    "https://github.com/88plug/license-watch/releases/latest/download/detect-linux-amd64",
)


@app.function(
    image=image,
    timeout=600,
    secrets=[modal.Secret.from_name("license-watch")],
)
@modal.fastapi_endpoint(method="POST")
def detect(payload: dict) -> dict:
    cursors_in = payload.get("cursors", {})
    watch_url = payload.get("watchlist_url")
    if not watch_url:
        return {"error": "missing watchlist_url"}

    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        # 1. Fetch detect binary
        bin_path = tmp / "detect"
        urllib.request.urlretrieve(DETECT_BIN_URL, bin_path)
        bin_path.chmod(0o755)

        # 2. Fetch watch.yml
        watch_path = tmp / "watch.yml"
        urllib.request.urlretrieve(watch_url, watch_path)

        # 3. Write cursors json
        cursors_path = tmp / "cursors.json"
        cursors_path.write_text(json.dumps(cursors_in))

        # 4. Run detector
        out_path = tmp / "candidates.jsonl"
        env = os.environ.copy()
        env["GH_TOKEN"] = os.environ.get("GH_TOKEN", "")
        env["REDDIT_CLIENT_ID"] = os.environ.get("REDDIT_CLIENT_ID", "")
        env["REDDIT_CLIENT_SECRET"] = os.environ.get("REDDIT_CLIENT_SECRET", "")
        env["YOUTUBE_API_KEY"] = os.environ.get("YOUTUBE_API_KEY", "")
        env["BIGQUERY_PROJECT"] = os.environ.get("BIGQUERY_PROJECT", "")

        proc = subprocess.run(
            [
                str(bin_path),
                f"--watch={watch_path}",
                f"--cursors={cursors_path}",
                f"--out={out_path}",
                "--cursors-out=" + str(tmp / "cursors-out.json"),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=540,
        )

        candidates = []
        if out_path.exists():
            for line in out_path.read_text().splitlines():
                line = line.strip()
                if line:
                    candidates.append(json.loads(line))

        cursors_out = cursors_in
        cursors_out_path = tmp / "cursors-out.json"
        if cursors_out_path.exists():
            cursors_out = json.loads(cursors_out_path.read_text())

        # TODO(L3): forward candidates to prefilter R2 bucket.
        return {
            "candidate_count": len(candidates),
            "cursors": cursors_out,
            "stderr_tail": proc.stderr[-2000:],
            "returncode": proc.returncode,
        }
