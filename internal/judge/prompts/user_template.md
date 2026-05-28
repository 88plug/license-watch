## Evidence package — candidate {{ candidate_url }}

### Our LICENSE (authoritative text)

```
{{ our_license_text }}
```

### Suspect repository LICENSE (as-fetched, may be empty)

```
{{ suspect_license_text or "(no LICENSE file detected)" }}
```

### Detector signals (L3 + L4)

- Clone type (Stage 1 classifier): **{{ clone_type }}**
- MinHash Jaccard similarity: **{{ minhash_score }}**
- TLSH hamming distance: **{{ tlsh_distance }}**
- Files matched: **{{ files_matched }}**
- Suspect repo stars: {{ stars }}, forks: {{ forks }}, age (days): {{ age_days }}
- Commercial signals: {{ commercial_signals or "(none detected)" }}

### Code diff snippets (top-{{ diff_count }} highest-similarity files)

{% for d in diffs %}
#### `{{ d.path }}` (Jaccard {{ d.score }})
```diff
{{ d.snippet }}
```
{% endfor %}

### Stage-1 clone-type rationale

{{ stage1_rationale }}

---

**Your task:** apply IRAC. Decide severity. Cite our license clauses by section. If you need case law, call `courtlistener_cite`. If you need fresh repo metadata, call `github_repo_metadata`. Return the JSON object specified in the system prompt — nothing else.
