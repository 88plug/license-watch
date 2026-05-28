"""Tool-use functions exposed to LLMs in the L5 judge.

All tools return JSON-serializable dicts. LLM tool-use schemas declared in
`judge.py` reference these by name.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import requests

# Repo root resolved relative to this file: internal/judge/tools.py -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
OUR_LICENSE = REPO_ROOT / "LICENSE.md"

USER_AGENT = "license-watch/L5-judge (https://github.com/88plug/license-watch)"
HTTP_TIMEOUT = 30


def grep_our_license(query: str, context_lines: int = 2) -> dict[str, Any]:
    """Case-insensitive substring/regex grep over our LICENSE.md.

    Returns matched line numbers + context. Used by judges to pin citations
    to actual clause text instead of hallucinating section numbers.
    """
    if not OUR_LICENSE.exists():
        return {"error": f"LICENSE.md not found at {OUR_LICENSE}", "matches": []}

    try:
        pattern = re.compile(query, re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(query), re.IGNORECASE)

    lines = OUR_LICENSE.read_text(encoding="utf-8").splitlines()
    matches: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if pattern.search(line):
            lo = max(0, i - context_lines)
            hi = min(len(lines), i + context_lines + 1)
            matches.append(
                {
                    "line": i + 1,
                    "text": line,
                    "context": "\n".join(lines[lo:hi]),
                }
            )
    return {"query": query, "match_count": len(matches), "matches": matches[:20]}


def courtlistener_cite(query: str, max_results: int = 5) -> dict[str, Any]:
    """Search CourtListener REST v3 for opinions matching a legal query.

    Docs: https://www.courtlistener.com/help/api/rest/
    Auth: optional. Set COURTLISTENER_TOKEN for higher rate limits.
    """
    token = os.environ.get("COURTLISTENER_TOKEN")
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Token {token}"

    url = "https://www.courtlistener.com/api/rest/v3/search/"
    params = {"type": "o", "q": query, "order_by": "score desc"}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return {"error": str(e), "results": []}

    results = []
    for hit in (data.get("results") or [])[:max_results]:
        results.append(
            {
                "case_name": hit.get("caseName"),
                "citation": hit.get("citation") or hit.get("lexisCite"),
                "court": hit.get("court"),
                "date_filed": hit.get("dateFiled"),
                "absolute_url": "https://www.courtlistener.com" + (hit.get("absolute_url") or ""),
                "snippet": (hit.get("snippet") or "")[:400],
            }
        )
    return {"query": query, "count": len(results), "results": results}


def github_repo_metadata(owner: str, repo: str) -> dict[str, Any]:
    """Fetch GitHub repo metadata. Uses GITHUB_TOKEN if set."""
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        d = r.json()
    except requests.RequestException as e:
        return {"error": str(e)}

    return {
        "full_name": d.get("full_name"),
        "description": d.get("description"),
        "stars": d.get("stargazers_count"),
        "forks": d.get("forks_count"),
        "watchers": d.get("subscribers_count"),
        "license": (d.get("license") or {}).get("spdx_id"),
        "default_branch": d.get("default_branch"),
        "created_at": d.get("created_at"),
        "pushed_at": d.get("pushed_at"),
        "archived": d.get("archived"),
        "fork": d.get("fork"),
        "homepage": d.get("homepage"),
    }


def fetch_url(url: str, max_bytes: int = 200_000) -> dict[str, Any]:
    """Fetch arbitrary URL (e.g. Wayback snapshot, project HTML page).

    Caps response size to avoid blowing the context window.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, stream=True)
        r.raise_for_status()
        body = r.raw.read(max_bytes, decode_content=True)
        text = body.decode("utf-8", errors="replace")
    except requests.RequestException as e:
        return {"error": str(e), "url": url}
    return {
        "url": url,
        "status": r.status_code,
        "content_type": r.headers.get("Content-Type"),
        "bytes": len(text),
        "text": text,
    }


# ---------- LLM tool-use schemas (Anthropic / OpenAI / Gemini compatible) ----

TOOL_SCHEMAS = [
    {
        "name": "grep_our_license",
        "description": "Search our LICENSE.md for a clause/phrase. Returns matched lines with surrounding context. Use this to pin every citation to real text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Substring or regex to search for."},
                "context_lines": {"type": "integer", "default": 2},
            },
            "required": ["query"],
        },
    },
    {
        "name": "courtlistener_cite",
        "description": "Search CourtListener case-law database for relevant opinions. Use for fair-use, copyright, and license-enforcement precedent. Never invent citations — call this first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "github_repo_metadata",
        "description": "Fetch GitHub repo metadata (stars, forks, license, archived flag, commercial signals).",
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch an arbitrary URL (HTML or text). Use for Wayback snapshots, pricing pages, README dumps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "max_bytes": {"type": "integer", "default": 200000},
            },
            "required": ["url"],
        },
    },
]

TOOL_DISPATCH = {
    "grep_our_license": grep_our_license,
    "courtlistener_cite": courtlistener_cite,
    "github_repo_metadata": github_repo_metadata,
    "fetch_url": fetch_url,
}


def dispatch(name: str, **kwargs: Any) -> dict[str, Any]:
    """Run a tool by name. Used by judge.py tool-loop."""
    fn = TOOL_DISPATCH.get(name)
    if not fn:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(**kwargs)
    except TypeError as e:
        return {"error": f"bad args for {name}: {e}"}
