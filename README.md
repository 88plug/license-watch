# license-watch

Best-in-the-world OSS license-violation + namesquat watch for solo devs.

[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue?style=flat-square)](LICENSE.md)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/88plug/license-watch)

8-layer pipeline. ~$10/mo all-in. Years-of-survival automation.

## What it watches

- **15 platforms**: GitHub + npm + PyPI + crates.io + Docker Hub + AUR + GHCR + Hugging Face + ArtifactHub + GitLab + Codeberg + Reddit + HN + Lobsters + Mastodon + Bluesky + Telegram + YouTube + Stack Overflow + dev.to
- **For every project in `watch.yml`** — your distinctive identifiers (function names, copyright strings, README embedding fingerprint, MinHash + TLSH per file)

## What it does

| Layer | Job |
|---|---|
| L1 | Cloudflare Workers cron (hourly) |
| L2 | Detection — firehoses + registry polls |
| L3 | Prefilter — MinHash + TLSH + MiniLM embedding cosine |
| L4 | Structural confirm — NiCad3 AST + FunctionSimSearch + custom osv-scalibr extractor |
| L5 | Semantic judge — Claude Haiku → 3-model consensus (Sonnet + GPT-5 + Gemini) → Opus tiebreak, IRAC prompting, CourtListener citation grounding |
| L6 | Evidence preserve — Browsertrix WACZ → SHA-256 → FreeTSA RFC 3161 + DigiCert + Sigstore Rekor + OpenTimestamps Bitcoin anchor → gitsign commit |
| L7 | Human gate — GitHub issue with pre-drafted DMCA you sign |
| L8 | Notify — Apprise → self-hosted ntfy.sh → phone + Matrix + Discord + email + weekly heartbeat |

## Status

Greenfield. Built layer by layer in parallel worktrees.

## License

FSL-1.1-ALv2 — see [LICENSE.md](LICENSE.md). Auto-converts to Apache 2.0 after 2 years per release.
