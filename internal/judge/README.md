# L5 — Semantic Judge

Tiered multi-LLM severity pipeline. Sits between L4 (confirm) and L6 (notice).

## Pipeline

| Stage | Model(s) | Cost | Purpose |
|-------|----------|------|---------|
| 1 — Classify | `claude-haiku-4-5` | ~$0.001 | Bellon clone-type (Type-1..4) |
| 2 — Consensus | `claude-sonnet-4-6`, `gpt-5`, `gemini-2.5-flash` | ~$0.05 | Independent IRAC severity vote, position-bias guarded |
| 3 — Tiebreak | `claude-opus-4-7` × 3 samples @ temp=0.7 | ~$0.03 | Only when no majority. Self-consistency (Wang 2022, arXiv 2203.11171). |

**Cost target: ≤$0.10 per candidate.** Anthropic prompt caching enabled on system + LICENSE block per the [official guide](https://docs.claude.com/en/docs/build-with-claude/prompt-caching) — ~90% saving on the cacheable prefix. Non-urgent batches should use the Anthropic batch API.

## Domain prompt (IRAC)

`prompts/system_irac.md` is the legal constitution. Encodes:

- FSL-1.1-ALv2 §1–§4 (Permitted Purpose, Competing Use, Change Date).
- SPDX identifier semantics + compatibility matrix.
- 17 USC §107 fair-use four factors (*Oracle v. Google*, 593 U.S. 1).
- Attribution duties (MIT/BSD/Apache NOTICE preservation).

Method follows IRAC + Legal Syllogism Prompting (arXiv 2307.08321). Multi-agent debate framing is informed by arXiv 2510.12697.

## Tool grounding

`tools.py` exposes four tools to every judge:

- `grep_our_license` — pins citations to real clause text.
- `courtlistener_cite` — case-law search via [CourtListener REST](https://www.courtlistener.com/help/api/rest/). Never hallucinate a citation.
- `github_repo_metadata` — stars, forks, license field, archived flag.
- `fetch_url` — HTML/Wayback fetch capped at 200 kB.

## Run

```bash
pip install -r requirements.txt
python -m internal.judge.judge --input confirmed.jsonl --output judgments.jsonl
```

## Eval gate

Promptfoo runs `eval/golden_cases.yaml` against Sonnet. CI fails if accuracy < 80% (`eval/gate.py`).

```bash
cd internal/judge/eval
npx promptfoo@latest eval -c promptfooconfig.yaml --output results.json
python gate.py --results results.json --threshold 0.80
```

## Schema (output JSONL)

See repo root `docs/ARCHITECTURE.md`. Each line:

```json
{
  "candidate_url": "...",
  "stage1_clone_type": "Type-2",
  "stage2_votes": [{"model": "claude-sonnet-4-6", "severity": "high", "...": "..."}, ...],
  "stage3_tiebreak": null,
  "final_severity": "high",
  "clauses_cited": ["FSL §3 Competing Use"],
  "case_law": ["Jacobsen v. Katzer, 535 F.3d 1373"],
  "draft_dmca": "<full text or empty>",
  "confidence": 0.87
}
```
