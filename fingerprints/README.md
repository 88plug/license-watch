# Reference fingerprints

One set per project being watched. Committed to repo so daily L3 jobs are reproducible
and the runner does not need network access to rebuild them.

## Files per project

- `{name}.readme.npy` — 384-dim MiniLM embedding of the project's README
- `{name}.minhash.json` — `{relative-file-path: minhash}` for every script file
- `{name}.tlsh.json` — `{relative-file-path: tlsh hex digest}` for every script file
- `fss/{name}.fssindex` (optional) — FunctionSimSearch index of compiled binaries

## Building

```
python scripts/build-fingerprints.py --repo ../intel-amt-linux --name intel-amt-linux
git add fingerprints/intel-amt-linux.*
git commit -m "fingerprints: add intel-amt-linux"
```

Model revision is pinned in `internal/prefilter/embed.py`; rebuilding on any machine
yields byte-identical embeddings.
