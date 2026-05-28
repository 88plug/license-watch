# Architecture

Eight layers, single Go binary (`watch`) + Python helpers for ML/CV components.

## Layers

### L1 Scheduling — `internal/scheduler/`
Cloudflare Workers Cron Trigger fires hourly → invokes Modal.com function (heavy CPU) or runs in-Worker (light tasks). State in Workers KV: last-seen cursor per source.

### L2 Detection / Firehose — `internal/detectors/`
Hourly poll of:
- GH Archive BigQuery (firehose: WatchEvent, ForkEvent, CreateEvent)
- npm `_changes?feed=continuous` long-poll
- ecosyste.ms `/api/v1` (30+ registries)
- AUR `/rpc/v5/search` + RSS
- Reddit OAuth, HN Algolia + Firebase, Lobsters RSS, Mastodon, Bluesky, Telegram t.me/s, YouTube v3, dev.to, Stack Exchange, Hugging Face, ArtifactHub, Docker Hub, GitLab, Codeberg

Output: `candidates.jsonl` — one per potential match.

### L3 Prefilter — `internal/prefilter/`
CPU-only, free runner. Each candidate vs reference fingerprints:
- MinHash winnowing (k=50 shingle)
- TLSH per file
- sentence-transformers `all-MiniLM-L6-v2` cosine on README + each script
- Threshold ≥0.85 → promote to L4

### L4 Structural Confirm — `internal/structural/`
- NiCad3 tree-sitter normalized clone detection
- FunctionSimSearch on binary artifacts (`-bin` packages)
- Custom osv-scalibr extractor with 88plug fingerprints

### L5 Semantic Judge — `internal/judge/`
Tiered LLM cascade:
- Claude Haiku 4.5 — classify Type-1/2/3/4 clone
- 3-model consensus: Claude Sonnet 4.6 + GPT-5 + Gemini 2.5 Flash vote on severity (IRAC prompt)
- Claude Opus 4.7 — tiebreaker on disagreement
- Tool calls: CourtListener Citation Lookup API, grep against `LICENSE.md`, fetch suspect repo metadata via GitHub MCP
- Output: `{severity, clause_cited, recommended_action, draft_dmca}`

### L6 Evidence Preserve — `internal/evidence/`
Per confirmed violation, in order:
1. Browsertrix WACZ capture of violator page + repo
2. SHA-256 of WACZ + raw HTML + screenshot + pHash
3. FreeTSA RFC 3161 timestamp
4. DigiCert RFC 3161 timestamp (redundant TSA)
5. Sigstore: `cosign sign-blob` → Rekor transparency log
6. OpenTimestamps `.ots` (Bitcoin anchor, ~3h)
7. `gitsign` commit all artifacts to evidence repo, push to multiple remotes

### L7 Human Gate — `internal/gate/`
Severity ≥ "high" → file GitHub issue in this repo. Body:
- Pre-drafted DMCA template populated by L5
- Evidence links + hashes + Rekor entry IDs + OTS confirmations
- Wayback + WACZ URLs
- Recommended action

You read, edit, sign. Manual paste to platform's takedown form.

### L8 Notify — `internal/notify/`
Apprise → self-hosted ntfy.sh ($4/mo Hetzner). Channels:
- Phone push
- Matrix room
- Discord webhook
- Email mirror
- Weekly heartbeat ("watcher alive")
- Apprise retry + exponential backoff + dead-letter to R2

## Costs

| Component | Cost |
|---|---|
| Cloudflare Workers | free |
| Modal.com | free tier (10 GPU-hr/mo) |
| BigQuery | free (<1TB/mo) |
| GitHub Actions | free (~100 min/mo) |
| Anthropic + OpenAI + Gemini | ~$3-7/mo with tiered routing + caching |
| Hetzner CX11 (ntfy + Browsertrix) | $4/mo |
| FreeTSA / Rekor / OTS | free |
| **Total** | **~$10-12/mo** |

## Watchlist format

```yaml
# watch.yml
projects:
  - name: intel-amt-linux
    github: 88plug/intel-amt-linux
    aur: intel-amt-linux
    distinctive_strings:
      - "Native Linux GUI + CLI for Intel AMT"
      - "imrsdk-linux"
    fingerprint:
      readme_embedding: ./fingerprints/intel-amt-linux.readme.npy
      file_minhash: ./fingerprints/intel-amt-linux.minhash.json
      tlsh: ./fingerprints/intel-amt-linux.tlsh.json
    license_path: LICENSE.md
```
