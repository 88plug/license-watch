"""L3 prefilter orchestrator.

Reads `candidates.jsonl` (one JSON per line, produced by L2). For each candidate
suspect repo:
  1. shallow-clone via `git clone --depth=1`
  2. compute MinHash on README + per-file
  3. compute TLSH per file
  4. compute MiniLM embedding on README + scripts
  5. compare vs reference fingerprints in fingerprints/{project}.{readme.npy,minhash.json,tlsh.json}
  6. emit `prefilter_hits.jsonl` if cosine ≥ 0.85 OR TLSH dist ≤ 30 OR Jaccard ≥ 0.5

CPU-only. Strict JSONL on stdout (none); only progress to stderr.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Optional

from . import embed, minhash, tlsh as tlsh_mod

log = logging.getLogger("prefilter")

# Files we care about — README + common script extensions. Skip binaries/lock files.
TEXT_EXTS = {
    ".py", ".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".sh", ".bash",
    ".c", ".cpp", ".h", ".hpp", ".java", ".kt", ".rb", ".php", ".lua",
    ".md", ".rst", ".txt", ".yml", ".yaml", ".toml",
}
README_NAMES = {"README.md", "README.rst", "README.txt", "README"}
MAX_FILE_BYTES = 1_000_000  # 1MB — skip generated/huge files


@dataclass
class Fingerprint:
    project: str
    readme_vec: "object"  # np.ndarray
    minhashes: dict       # filename → LeanMinHash
    tlsh_digests: dict    # filename → tlsh hex


@dataclass
class Hit:
    project: str
    candidate_url: str
    candidate_path: str
    score_cosine: float
    score_tlsh_min: int
    score_jaccard_max: float
    matched_files: list

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def load_fingerprint(fp_dir: Path, project: str) -> Fingerprint:
    readme = embed.load(fp_dir / f"{project}.readme.npy")
    mh_data = json.loads((fp_dir / f"{project}.minhash.json").read_text())
    minhashes = {fname: minhash.from_dict(md) for fname, md in mh_data.items()}
    tlsh_data = json.loads((fp_dir / f"{project}.tlsh.json").read_text())
    return Fingerprint(
        project=project,
        readme_vec=readme,
        minhashes=minhashes,
        tlsh_digests=tlsh_data,
    )


def discover_fingerprints(fp_dir: Path) -> list[str]:
    return sorted({p.name.split(".")[0] for p in fp_dir.glob("*.readme.npy")})


def shallow_clone(url: str, dest: Path) -> bool:
    """git clone --depth=1. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", url, str(dest)],
            check=True,
            capture_output=True,
            timeout=300,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning("clone failed for %s: %s", url, e)
        return False


def iter_text_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # skip .git, vendor, node_modules
        if any(part in {".git", "node_modules", "vendor", "dist", "build", "target"} for part in p.parts):
            continue
        if p.suffix.lower() not in TEXT_EXTS and p.name not in README_NAMES:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def read_text(p: Path) -> Optional[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def find_readme(root: Path) -> Optional[Path]:
    for name in README_NAMES:
        p = root / name
        if p.exists():
            return p
    # fallback: any README* at top level
    for p in root.iterdir():
        if p.is_file() and p.name.lower().startswith("readme"):
            return p
    return None


def score_candidate(repo: Path, fp: Fingerprint, cache_dir: Path) -> tuple[float, int, float, list[str]]:
    """Return (max cosine, min tlsh dist, max jaccard, matched filenames)."""
    matched: list[str] = []

    # README cosine
    cos = 0.0
    readme_path = find_readme(repo)
    if readme_path is not None:
        rd = read_text(readme_path)
        if rd:
            try:
                vec = embed.embed(rd, cache_dir=cache_dir)
                cos = embed.cosine(vec, fp.readme_vec)
                if cos >= embed.COSINE_MATCH:
                    matched.append(readme_path.name)
            except Exception as e:
                log.warning("embed failed for %s: %s", readme_path, e)

    # Per-file MinHash + TLSH
    min_tlsh = 10_000
    max_jac = 0.0
    for f in iter_text_files(repo):
        txt = read_text(f)
        if not txt:
            continue
        try:
            cand_mh = minhash.build_minhash(txt)
        except Exception:
            continue
        for fname, ref_mh in fp.minhashes.items():
            j = minhash.jaccard(cand_mh, ref_mh)
            if j > max_jac:
                max_jac = j
            if j >= 0.5 and f.name not in matched:
                matched.append(f.name)

        try:
            cand_tlsh = tlsh_mod.hash_bytes(txt.encode("utf-8", errors="replace"))
        except Exception:
            cand_tlsh = None
        if cand_tlsh:
            for fname, ref_tlsh in fp.tlsh_digests.items():
                try:
                    d = tlsh_mod.distance(cand_tlsh, ref_tlsh)
                except Exception:
                    continue
                if d < min_tlsh:
                    min_tlsh = d
                if d <= tlsh_mod.DISTANCE_MATCH and f.name not in matched:
                    matched.append(f.name)

    return cos, min_tlsh, max_jac, matched


def process_candidate(candidate: dict, fingerprints: list[Fingerprint], cache_dir: Path) -> list[Hit]:
    """Clone candidate.url, score vs each fingerprint, return hits."""
    url = candidate.get("url") or candidate.get("html_url") or candidate.get("repo")
    if not url:
        log.warning("candidate missing url: %s", candidate)
        return []

    hits: list[Hit] = []
    with tempfile.TemporaryDirectory(prefix="lw-l3-") as td:
        dest = Path(td) / "repo"
        if not shallow_clone(url, dest):
            return []

        for fp in fingerprints:
            cos, td_min, jac_max, matched = score_candidate(dest, fp, cache_dir)
            if cos >= embed.COSINE_MATCH or td_min <= tlsh_mod.DISTANCE_MATCH or jac_max >= 0.5:
                hits.append(Hit(
                    project=fp.project,
                    candidate_url=url,
                    candidate_path=str(dest),
                    score_cosine=cos,
                    score_tlsh_min=td_min,
                    score_jaccard_max=jac_max,
                    matched_files=matched,
                ))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="license-watch L3 prefilter")
    ap.add_argument("--candidates", type=Path, required=True, help="candidates.jsonl input")
    ap.add_argument("--fingerprints", type=Path, default=Path("fingerprints"), help="reference fingerprints dir")
    ap.add_argument("--output", type=Path, required=True, help="prefilter_hits.jsonl output")
    ap.add_argument("--cache-dir", type=Path, default=Path(".cache/embed"), help="embedding cache dir")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)

    logging.basicConfig(level=args.log_level, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")

    projects = discover_fingerprints(args.fingerprints)
    if not projects:
        log.error("no fingerprints in %s", args.fingerprints)
        return 2
    log.info("loaded %d fingerprints: %s", len(projects), projects)
    fingerprints = [load_fingerprint(args.fingerprints, p) for p in projects]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n_in = 0
    n_hits = 0
    with args.candidates.open() as fin, args.output.open("w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                cand = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning("bad json line: %s", e)
                continue
            for hit in process_candidate(cand, fingerprints, args.cache_dir):
                fout.write(hit.to_json() + "\n")
                fout.flush()
                n_hits += 1
    log.info("processed %d candidates → %d hits", n_in, n_hits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
