"""L5 — Semantic Judge for license-watch.

Three-stage tiered multi-LLM severity pipeline.

Stage 1 — cheap clone-type classification (Claude Haiku 4.5).
Stage 2 — 3-model consensus via structured IRAC prompt
          (Claude Sonnet 4.6 + GPT-5 + Gemini 2.5 Flash).
          Majority-vote severity, position-bias guard by shuffling order.
Stage 3 — tiebreak when no majority: Claude Opus 4.7 reads all three Stage-2
          rationales + raw evidence and decides. Self-consistency: 3 samples
          @ temp=0.7, majority over those samples (Wang et al. 2022,
          arXiv 2203.11171).

Anthropic prompt caching enabled on system prompt + LICENSE block
(https://docs.claude.com/en/docs/build-with-claude/prompt-caching).
Cost target ≤$0.10 per candidate on typical evidence package.

Input:  confirmed.jsonl (from L4)
Output: judgments.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Template

from . import tools  # noqa: TID252  -- package-relative

# ---------------------------------------------------------------------------
# Model IDs — pinned per spec. Update only with benchmark evidence.
# ---------------------------------------------------------------------------
MODEL_HAIKU = "claude-haiku-4-5"
MODEL_SONNET = "claude-sonnet-4-6"
MODEL_OPUS = "claude-opus-4-7"
MODEL_GPT5 = "gpt-5"
MODEL_GEMINI = "gemini-2.5-flash"

PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT = (PROMPTS_DIR / "system_irac.md").read_text(encoding="utf-8")
USER_TEMPLATE = Template((PROMPTS_DIR / "user_template.md").read_text(encoding="utf-8"))

REPO_ROOT = Path(__file__).resolve().parents[2]
OUR_LICENSE_TEXT = (REPO_ROOT / "LICENSE.md").read_text(encoding="utf-8") if (REPO_ROOT / "LICENSE.md").exists() else ""

SEVERITY_ORDER = {"low": 0, "med": 1, "high": 2}

# ---------------------------------------------------------------------------
# Lazy client init — keeps import cheap and lets tests stub.
# ---------------------------------------------------------------------------


def _anthropic_client():
    import anthropic
    return anthropic.Anthropic()


def _openai_client():
    import openai
    return openai.OpenAI()


def _gemini_client():
    import google.generativeai as genai
    genai.configure(api_key=os.environ["GOOGLE_AI_API_KEY"])
    return genai


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def render_user_prompt(candidate: dict[str, Any], clone_type: str, stage1_rationale: str) -> str:
    diffs = candidate.get("diffs") or []
    return USER_TEMPLATE.render(
        candidate_url=candidate.get("candidate_url", ""),
        our_license_text=OUR_LICENSE_TEXT,
        suspect_license_text=candidate.get("suspect_license_text", ""),
        clone_type=clone_type,
        minhash_score=candidate.get("minhash_score"),
        tlsh_distance=candidate.get("tlsh_distance"),
        files_matched=candidate.get("files_matched"),
        stars=candidate.get("stars"),
        forks=candidate.get("forks"),
        age_days=candidate.get("age_days"),
        commercial_signals=candidate.get("commercial_signals"),
        diff_count=len(diffs),
        diffs=diffs,
        stage1_rationale=stage1_rationale,
    )


# ---------------------------------------------------------------------------
# Stage 1 — cheap classify
# ---------------------------------------------------------------------------

STAGE1_SYSTEM = (
    "You classify code-clone type per Bellon et al. taxonomy. "
    "Return strict JSON: {\"clone_type\": \"Type-1|Type-2|Type-3|Type-4\", \"rationale\": \"...\"}."
    " Type-1 = verbatim. Type-2 = renamed identifiers. Type-3 = near-miss with edits. "
    "Type-4 = semantically equivalent, different syntax. No prose outside JSON."
)


def stage1_classify(candidate: dict[str, Any]) -> tuple[str, str]:
    """Haiku-cheap classify. Returns (clone_type, rationale)."""
    diffs = candidate.get("diffs") or []
    snippet_blob = "\n\n".join(f"### {d.get('path')}\n{d.get('snippet','')}" for d in diffs[:3])
    user = (
        f"MinHash Jaccard: {candidate.get('minhash_score')}\n"
        f"TLSH distance: {candidate.get('tlsh_distance')}\n"
        f"Top diffs:\n{snippet_blob}\n\nClassify."
    )

    client = _anthropic_client()
    resp = client.messages.create(
        model=MODEL_HAIKU,
        max_tokens=400,
        system=STAGE1_SYSTEM,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    try:
        obj = json.loads(_strip_fences(text))
        return obj.get("clone_type", "Type-3"), obj.get("rationale", "")
    except json.JSONDecodeError:
        return "Type-3", text[:500]


# ---------------------------------------------------------------------------
# Stage 2 — 3-model consensus
# ---------------------------------------------------------------------------


@dataclass
class Vote:
    model: str
    severity: str
    reasoning: str
    clauses_cited: list[str] = field(default_factory=list)
    case_law: list[str] = field(default_factory=list)
    recommended_action: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        # remove first fence line
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.endswith("```"):
            s = s[: -3]
    return s.strip()


def _parse_judge_json(text: str, model: str) -> Vote:
    try:
        obj = json.loads(_strip_fences(text))
    except json.JSONDecodeError:
        return Vote(model=model, severity="low", reasoning=f"PARSE_ERROR: {text[:300]}", raw={"text": text})
    sev = (obj.get("severity") or "low").lower()
    if sev not in SEVERITY_ORDER:
        sev = "low"
    return Vote(
        model=model,
        severity=sev,
        reasoning=obj.get("reasoning") or obj.get("application") or "",
        clauses_cited=obj.get("clauses_cited") or [],
        case_law=obj.get("case_law") or [],
        recommended_action=obj.get("recommended_action") or "",
        raw=obj,
    )


def _anthropic_judge(model: str, user_prompt: str, temperature: float = 0.0) -> Vote:
    client = _anthropic_client()
    # Prompt caching: mark system + LICENSE block as cacheable (90% saving).
    system_blocks = [
        {"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}},
    ]
    resp = client.messages.create(
        model=model,
        max_tokens=1500,
        temperature=temperature,
        system=system_blocks,
        messages=[{"role": "user", "content": user_prompt}],
        extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    return _parse_judge_json(text, model)


def _openai_judge(model: str, user_prompt: str, temperature: float = 0.0) -> Vote:
    client = _openai_client()
    resp = client.chat.completions.create(
        model=model,
        temperature=temperature,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    text = resp.choices[0].message.content or ""
    return _parse_judge_json(text, model)


def _gemini_judge(model: str, user_prompt: str, temperature: float = 0.0) -> Vote:
    genai = _gemini_client()
    m = genai.GenerativeModel(model, system_instruction=SYSTEM_PROMPT)
    resp = m.generate_content(
        user_prompt,
        generation_config={"temperature": temperature, "response_mime_type": "application/json"},
    )
    text = getattr(resp, "text", "") or ""
    return _parse_judge_json(text, model)


def stage2_consensus(candidate: dict[str, Any], clone_type: str, stage1_rationale: str) -> list[Vote]:
    """Send same IRAC prompt to 3 models. Shuffle evidence diff order per model
    to guard against position bias."""
    votes: list[Vote] = []

    base_diffs = list(candidate.get("diffs") or [])
    permutations = [base_diffs, list(reversed(base_diffs)), _shuffled(base_diffs)]

    for model_call, perm in zip(
        [
            ("anthropic", MODEL_SONNET),
            ("openai", MODEL_GPT5),
            ("gemini", MODEL_GEMINI),
        ],
        permutations,
    ):
        c = dict(candidate)
        c["diffs"] = perm
        prompt = render_user_prompt(c, clone_type, stage1_rationale)
        provider, model_id = model_call
        try:
            if provider == "anthropic":
                vote = _anthropic_judge(model_id, prompt)
            elif provider == "openai":
                vote = _openai_judge(model_id, prompt)
            else:
                vote = _gemini_judge(model_id, prompt)
        except Exception as e:  # noqa: BLE001 -- never let one model kill batch
            vote = Vote(model=model_id, severity="low", reasoning=f"API_ERROR: {e}")
        votes.append(vote)

    return votes


def _shuffled(items: list[Any]) -> list[Any]:
    items = list(items)
    rng = random.Random(0xC0FFEE)
    rng.shuffle(items)
    return items


# ---------------------------------------------------------------------------
# Stage 3 — tiebreak with self-consistency
# ---------------------------------------------------------------------------


def stage3_tiebreak(candidate: dict[str, Any], clone_type: str, stage1_rationale: str, votes: list[Vote]) -> Vote:
    """Opus reads everyone's reasoning + raw evidence, decides final severity.
    Self-consistency: 3 samples at temp=0.7, majority-vote severity."""
    base_prompt = render_user_prompt(candidate, clone_type, stage1_rationale)
    panel = "\n\n".join(
        f"### {v.model} voted {v.severity}\nreasoning: {v.reasoning}\nclauses_cited: {v.clauses_cited}\ncase_law: {v.case_law}\nrecommended_action: {v.recommended_action}"
        for v in votes
    )
    prompt = (
        base_prompt
        + "\n\n---\n\n## Panel disagreed. Three judges:\n"
        + panel
        + "\n\nReweigh evidence. Resolve disagreement. Apply IRAC. Return the JSON object."
    )

    samples: list[Vote] = []
    for _ in range(3):
        try:
            samples.append(_anthropic_judge(MODEL_OPUS, prompt, temperature=0.7))
        except Exception as e:  # noqa: BLE001
            samples.append(Vote(model=MODEL_OPUS, severity="low", reasoning=f"API_ERROR: {e}"))

    # Majority over the 3 Opus samples
    counter = Counter(s.severity for s in samples)
    top_sev, _ = counter.most_common(1)[0]
    # Return the first sample matching that severity (preserves reasoning).
    for s in samples:
        if s.severity == top_sev:
            return s
    return samples[0]


# ---------------------------------------------------------------------------
# Voting math
# ---------------------------------------------------------------------------


def majority_severity(votes: list[Vote]) -> tuple[str | None, bool]:
    """Return (severity, has_majority). If no strict majority, return (None, False)."""
    if not votes:
        return None, False
    counter = Counter(v.severity for v in votes)
    top, count = counter.most_common(1)[0]
    return (top, count > len(votes) / 2)


def confidence_score(votes: list[Vote], final_severity: str) -> float:
    """Simple agreement-weighted confidence in [0,1]."""
    if not votes:
        return 0.0
    agree = sum(1 for v in votes if v.severity == final_severity)
    return round(agree / len(votes), 3)


# ---------------------------------------------------------------------------
# DMCA draft
# ---------------------------------------------------------------------------


def draft_dmca(candidate: dict[str, Any], final_severity: str, clauses: list[str], case_law: list[str]) -> str:
    if final_severity != "high":
        return ""
    return f"""DMCA TAKEDOWN NOTICE — DRAFT (review with counsel before sending)

To: DMCA Agent, GitHub, Inc.
Date: (auto-fill on send)

1. Identification of copyrighted work:
   The original software is published at https://github.com/88plug/license-watch under FSL-1.1-ALv2.
   Copyright (c) Andrew Mello, 88plug.

2. Identification of infringing material:
   {candidate.get('candidate_url')}
   Files matched: {candidate.get('files_matched')}
   MinHash Jaccard: {candidate.get('minhash_score')}, TLSH distance: {candidate.get('tlsh_distance')}.

3. Clauses violated:
   {chr(10).join('   - ' + c for c in clauses)}

4. Supporting precedent:
   {chr(10).join('   - ' + c for c in case_law)}

5. Good-faith statement:
   I have a good-faith belief that use of the material described above is not authorized by the
   copyright owner, its agent, or the law.

6. Statement of accuracy:
   The information in this notification is accurate, and under penalty of perjury, I am the
   owner, or authorized to act on behalf of the owner, of an exclusive right that is allegedly
   infringed.

Signature: Andrew Mello
Contact:   andrew@88plug.com
"""


# ---------------------------------------------------------------------------
# Pipeline driver
# ---------------------------------------------------------------------------


def judge_one(candidate: dict[str, Any]) -> dict[str, Any]:
    """Run full L5 pipeline on a single candidate. Returns judgment dict."""
    clone_type, stage1_rationale = stage1_classify(candidate)

    votes = stage2_consensus(candidate, clone_type, stage1_rationale)
    maj_sev, has_majority = majority_severity(votes)

    tiebreak_vote: Vote | None = None
    if not has_majority:
        tiebreak_vote = stage3_tiebreak(candidate, clone_type, stage1_rationale, votes)
        final_severity = tiebreak_vote.severity
    else:
        assert maj_sev is not None
        final_severity = maj_sev

    # Union clauses + case law across votes that agree with final severity.
    citing = [v for v in votes if v.severity == final_severity]
    if tiebreak_vote is not None:
        citing.append(tiebreak_vote)
    clauses = sorted({c for v in citing for c in v.clauses_cited})
    case_law = sorted({c for v in citing for c in v.case_law})

    confidence = confidence_score(votes + ([tiebreak_vote] if tiebreak_vote else []), final_severity)

    return {
        "candidate_url": candidate.get("candidate_url"),
        "stage1_clone_type": clone_type,
        "stage1_rationale": stage1_rationale,
        "stage2_votes": [
            {
                "model": v.model,
                "severity": v.severity,
                "reasoning": v.reasoning,
                "clauses_cited": v.clauses_cited,
                "case_law": v.case_law,
                "recommended_action": v.recommended_action,
            }
            for v in votes
        ],
        "stage3_tiebreak": (
            {
                "model": tiebreak_vote.model,
                "severity": tiebreak_vote.severity,
                "reasoning": tiebreak_vote.reasoning,
            }
            if tiebreak_vote
            else None
        ),
        "final_severity": final_severity,
        "clauses_cited": clauses,
        "case_law": case_law,
        "draft_dmca": draft_dmca(candidate, final_severity, clauses, case_law),
        "confidence": confidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="L5 semantic judge")
    parser.add_argument("--input", required=True, help="Path to confirmed.jsonl from L4")
    parser.add_argument("--output", required=True, help="Path to judgments.jsonl")
    parser.add_argument("--limit", type=int, default=None, help="Cap candidates (for cost control)")
    args = parser.parse_args(argv)

    inp = Path(args.input)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    n = 0
    with inp.open() as fin, out.open("w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            candidate = json.loads(line)
            judgment = judge_one(candidate)
            fout.write(json.dumps(judgment) + "\n")
            fout.flush()
            n += 1
            if args.limit and n >= args.limit:
                break

    print(f"L5: judged {n} candidate(s) -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
