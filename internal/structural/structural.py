"""L4 structural-confirm orchestrator.

Reads `prefilter_hits.jsonl` (output of L3) and, for each hit:
  1. NiCad3 functions/blocks AST clones (Type-1/2/3) between reference repo and candidate
  2. FunctionSimSearch — only if candidate has `-bin` artifacts (compiled)
  3. osv-scalibr custom Detector — string + symbol matching with 88plug signatures

Confirmed if any one of:
  - NiCad3 reports ≥1 cross-tree clone pair with similarity ≥ 70%
  - FunctionSimSearch finds ≥3 matching functions with Hamming ≤ 32
  - scalibr Detector returns any Finding (i.e. ≥ project's min_hits markers)

Output: `confirmed.jsonl` — one JSON per confirmed match.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from . import nicad3

log = logging.getLogger("structural")

FSS_BIN = os.environ.get("LW_FSS_BIN", "lw-functionsimsearch")
SCALIBR_BIN = os.environ.get("LW_SCALIBR_BIN", "lw-scalibr-fp")
FSS_MIN_FUNCS = 3


@dataclass
class Confirmed:
    project: str
    candidate_url: str
    method: str
    detail: dict = field(default_factory=dict)
    prefilter_score_cosine: float = 0.0
    prefilter_score_tlsh_min: int = 10_000
    prefilter_score_jaccard_max: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def _shallow_clone(url: str, dest: Path) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", url, str(dest)],
            check=True, capture_output=True, timeout=300,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning("clone failed for %s: %s", url, e)
        return False


def run_scalibr(signatures: Path, root: Path) -> list[dict]:
    """Invoke lw-scalibr-fp. Returns list of Finding dicts (empty if binary missing)."""
    try:
        proc = subprocess.run(
            [SCALIBR_BIN, "--signatures", str(signatures), "--root", str(root)],
            capture_output=True, text=True, timeout=300, check=True,
        )
    except FileNotFoundError:
        log.warning("scalibr binary %s not found — skipping", SCALIBR_BIN)
        return []
    except subprocess.CalledProcessError as e:
        log.warning("scalibr failed: %s", e.stderr.strip()[:500])
        return []
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def run_functionsimsearch(index: Path, candidate_binary: Path) -> list[dict]:
    try:
        proc = subprocess.run(
            [FSS_BIN, "--index", str(index), "--binary", str(candidate_binary)],
            capture_output=True, text=True, timeout=600, check=True,
        )
    except FileNotFoundError:
        log.warning("fss binary %s not found — skipping", FSS_BIN)
        return []
    except subprocess.CalledProcessError as e:
        log.warning("fss failed: %s", e.stderr.strip()[:500])
        return []
    matches = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            matches.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return matches


def find_binaries(root: Path) -> list[Path]:
    """Return likely binary artifacts under root (-bin packages)."""
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # heuristic: ELF or Mach-O magic
        try:
            with p.open("rb") as fh:
                magic = fh.read(4)
        except OSError:
            continue
        if magic[:4] == b"\x7fELF" or magic[:4] in (b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"):
            out.append(p)
    return out


def detect_language(repo: Path) -> str:
    """Naive language guess for NiCad based on file-count majority."""
    counts: dict[str, int] = {}
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in (".py",):
            counts["py"] = counts.get("py", 0) + 1
        elif ext in (".go",):
            counts["go"] = counts.get("go", 0) + 1
        elif ext in (".c", ".h"):
            counts["c"] = counts.get("c", 0) + 1
        elif ext in (".java",):
            counts["java"] = counts.get("java", 0) + 1
    if not counts:
        return "py"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def process_hit(hit: dict, reference_dir: Path, signatures: Path,
                fss_indexes: dict[str, Path]) -> list[Confirmed]:
    project = hit["project"]
    url = hit["candidate_url"]
    confirms: list[Confirmed] = []

    with tempfile.TemporaryDirectory(prefix="lw-l4-") as td:
        cand = Path(td) / "candidate"
        if not _shallow_clone(url, cand):
            return []

        ref_path = reference_dir / project
        if not ref_path.exists():
            log.warning("no reference repo at %s — skipping NiCad", ref_path)
        else:
            lang = detect_language(ref_path)
            ok, pairs = nicad3.has_clone(ref_path, cand, language=lang)
            if ok:
                confirms.append(Confirmed(
                    project=project, candidate_url=url, method="nicad3",
                    detail={"pairs": [p.to_dict() for p in pairs[:25]], "language": lang},
                    prefilter_score_cosine=hit.get("score_cosine", 0.0),
                    prefilter_score_tlsh_min=hit.get("score_tlsh_min", 10000),
                    prefilter_score_jaccard_max=hit.get("score_jaccard_max", 0.0),
                ))

        # scalibr
        findings = run_scalibr(signatures, cand)
        for f in findings:
            if f.get("project") == project:
                confirms.append(Confirmed(
                    project=project, candidate_url=url, method="scalibr",
                    detail=f,
                    prefilter_score_cosine=hit.get("score_cosine", 0.0),
                    prefilter_score_tlsh_min=hit.get("score_tlsh_min", 10000),
                    prefilter_score_jaccard_max=hit.get("score_jaccard_max", 0.0),
                ))

        # FunctionSimSearch — only if we have an index for this project
        idx = fss_indexes.get(project)
        if idx and idx.exists():
            matches: list[dict] = []
            for bin_path in find_binaries(cand):
                matches.extend(run_functionsimsearch(idx, bin_path))
            if len(matches) >= FSS_MIN_FUNCS:
                confirms.append(Confirmed(
                    project=project, candidate_url=url, method="functionsimsearch",
                    detail={"match_count": len(matches), "samples": matches[:10]},
                    prefilter_score_cosine=hit.get("score_cosine", 0.0),
                    prefilter_score_tlsh_min=hit.get("score_tlsh_min", 10000),
                    prefilter_score_jaccard_max=hit.get("score_jaccard_max", 0.0),
                ))

    return confirms


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="license-watch L4 structural confirm")
    ap.add_argument("--hits", type=Path, required=True, help="prefilter_hits.jsonl input")
    ap.add_argument("--reference-dir", type=Path, default=Path("references"),
                    help="dir containing reference repos named after each project")
    ap.add_argument("--signatures", type=Path, default=Path("internal/structural/signatures.json"))
    ap.add_argument("--fss-index-dir", type=Path, default=Path("fingerprints/fss"),
                    help="dir with <project>.fssindex files")
    ap.add_argument("--output", type=Path, required=True, help="confirmed.jsonl output")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)

    logging.basicConfig(level=args.log_level, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")

    fss_indexes: dict[str, Path] = {}
    if args.fss_index_dir.exists():
        for p in args.fss_index_dir.glob("*.fssindex"):
            fss_indexes[p.stem] = p

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n_in = 0
    n_confirmed = 0
    with args.hits.open() as fin, args.output.open("w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                hit = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning("bad json: %s", e)
                continue
            for c in process_hit(hit, args.reference_dir, args.signatures, fss_indexes):
                fout.write(c.to_json() + "\n")
                fout.flush()
                n_confirmed += 1
    log.info("processed %d hits → %d confirmed", n_in, n_confirmed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
