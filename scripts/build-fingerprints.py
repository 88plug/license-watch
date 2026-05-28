#!/usr/bin/env python3
"""Build reference fingerprint set for a project.

Usage:
    python scripts/build-fingerprints.py --repo /path/to/project --name my-project \\
        --out fingerprints/

Emits:
    fingerprints/{name}.readme.npy     — MiniLM embedding of README
    fingerprints/{name}.minhash.json   — {filename: minhash} per script file
    fingerprints/{name}.tlsh.json      — {filename: tlsh hex} per script file

Run once per project; commit the fingerprints/ artifacts to the repo. Reproducible
because model revision is pinned in internal/prefilter/embed.py.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Make repo root importable when script run directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from internal.prefilter import embed, minhash, tlsh as tlsh_mod  # noqa: E402
from internal.prefilter.prefilter import (  # noqa: E402
    iter_text_files,
    find_readme,
    read_text,
)

log = logging.getLogger("build-fingerprints")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build reference fingerprint set")
    ap.add_argument("--repo", type=Path, required=True, help="path to project repo")
    ap.add_argument("--name", required=True, help="project short name (used in filenames)")
    ap.add_argument("--out", type=Path, default=Path("fingerprints"))
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)

    logging.basicConfig(level=args.log_level, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")

    if not args.repo.is_dir():
        log.error("repo not a directory: %s", args.repo)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)

    # README embedding
    readme = find_readme(args.repo)
    if not readme:
        log.error("no README found in %s", args.repo)
        return 2
    rd = read_text(readme) or ""
    vec = embed.embed(rd)
    embed.save(args.out / f"{args.name}.readme.npy", vec)
    log.info("wrote %s.readme.npy (dim=%d)", args.name, vec.shape[0])

    # MinHash + TLSH per file
    mh_out: dict[str, dict] = {}
    tlsh_out: dict[str, str] = {}
    for f in iter_text_files(args.repo):
        rel = f.relative_to(args.repo).as_posix()
        txt = read_text(f)
        if not txt:
            continue
        try:
            mh = minhash.build_minhash(txt)
            mh_out[rel] = minhash.to_dict(mh)
        except Exception as e:
            log.warning("minhash failed for %s: %s", rel, e)
        try:
            th = tlsh_mod.hash_bytes(txt.encode("utf-8", errors="replace"))
            if th:
                tlsh_out[rel] = th
        except Exception as e:
            log.warning("tlsh failed for %s: %s", rel, e)

    (args.out / f"{args.name}.minhash.json").write_text(
        json.dumps(mh_out, sort_keys=True, indent=2)
    )
    (args.out / f"{args.name}.tlsh.json").write_text(
        json.dumps(tlsh_out, sort_keys=True, indent=2)
    )
    log.info("wrote %d minhashes, %d tlsh digests", len(mh_out), len(tlsh_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
