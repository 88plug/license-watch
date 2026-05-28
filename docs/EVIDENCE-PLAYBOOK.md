# Evidence Recovery & Verification Playbook (L6)

This is the operational guide for **proving** that a preserved
license-violation evidence bundle is authentic, untampered, and was
captured at (or before) the time license-watch claims. Use it before
filing a DMCA notice, opposing a counter-notice, or attaching exhibits
to a complaint.

The chain is engineered so that **independent third parties** can run
every verification step — no trust in 88plug, no trust in
license-watch, no trust in any single TSA, log, or remote required.

---

## 0. Layout

Every preserved violation lives at:

```
evidence/{candidate-id}/
  MANIFEST.json          # human-readable manifest
  MANIFEST.jsonl         # one-line, machine-parseable
  *.wacz                 # Browsertrix archive (primary)
  *.html                 # raw HTML fallback
  *.png                  # full-page Playwright screenshot
  *.phash.json           # perceptual hashes (pHash/dHash)
  *.<TSA>.tsr            # RFC 3161 reply per TSA
  *.cosign.bundle        # Sigstore Rekor bundle
  *.cosign.bundle.uuid   # Rekor entry UUID (sidecar)
  *.ots                  # OpenTimestamps Bitcoin attestation
```

`MANIFEST.json` is the authoritative record. Every other file is
referenced by SHA-256 + SHA-512 from inside the manifest.

---

## 1. Re-hash every artifact

Confirms nothing on disk has been altered since the manifest sealed.

```bash
jq -r '.artifacts[] | "\(.sha256)  \(.path)"' MANIFEST.json | sha256sum -c
jq -r '.artifacts[] | "\(.sha512)  \(.path)"' MANIFEST.json | sha512sum -c
```

Every line must report `OK`. A single failure means the bundle has
been tampered with (or transferred lossily) and must be discarded.

The Go helper does the same:

```bash
preserve --verify ./evidence/c-001/MANIFEST.json
```

---

## 2. Verify each RFC 3161 TSR

We use **two independent TSAs** (FreeTSA + DigiCert). A court can
verify either one without trusting the other. Get the root chains
once and cache them.

```bash
# FreeTSA chain (one-time)
curl -fsSL -o freetsa-cacert.pem  https://freetsa.org/files/cacert.pem
curl -fsSL -o freetsa-tsa.pem     https://freetsa.org/files/tsa.crt

# DigiCert chain (one-time)
curl -fsSL -o digicert-ca.pem \
  https://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem

# Verify each TSR against its source artifact
openssl ts -verify \
  -in   evidence/c-001/foo.wacz.FreeTSA.tsr \
  -data evidence/c-001/foo.wacz \
  -CAfile freetsa-cacert.pem -untrusted freetsa-tsa.pem

openssl ts -verify \
  -in   evidence/c-001/foo.wacz.DigiCert.tsr \
  -data evidence/c-001/foo.wacz \
  -CAfile digicert-ca.pem
```

`Verification: OK` from at least ONE TSA is sufficient — both is the
norm and demonstrates redundant attestation.

---

## 3. Verify the Sigstore Rekor entry

Rekor is an append-only Merkle-tree transparency log. The cosign
bundle contains the Signed Entry Timestamp (SET) and inclusion proof.

```bash
# Re-verify locally, no network
cosign verify-blob \
  --bundle    evidence/c-001/foo.wacz.cosign.bundle \
  --certificate-identity      "andrew@88plug.com" \
  --certificate-oidc-issuer   "https://token.actions.githubusercontent.com" \
  evidence/c-001/foo.wacz

# Cross-check public log
UUID=$(cat evidence/c-001/foo.wacz.cosign.bundle.uuid)
rekor-cli get --uuid "$UUID" --format json | jq .
```

Match the `logIndex` and `integratedTime` against `MANIFEST.json`.

---

## 4. Verify the OpenTimestamps Bitcoin attestation

This is the strongest, most adversary-resistant anchor: the SHA-256
of the artifact is commited into a Bitcoin block. Confirmation takes
~3–6 hours after capture. After that, anyone with a Bitcoin node can
verify without trusting any third party at all.

```bash
# First, upgrade the attestation with the calendar's latest proof
ots upgrade evidence/c-001/foo.wacz.ots

# Then verify
ots verify evidence/c-001/foo.wacz.ots
```

Expected success line:

```
Success! Bitcoin block <NNNNNN> attests existence as of <DATE>
```

If you do not run a Bitcoin node, `ots verify` queries a public
calendar; the proof is still cryptographically sound.

> Reference: **Paris Judicial Court, 20 Mar 2025** accepted an
> OpenTimestamps attestation as proof of prior art in a copyright
> case — establishing precedent for OTS evidence admissibility.

---

## 5. Authenticate the WACZ archive

WACZ packs WARC + signed metadata + datapackage-digest. The
`webrecorder` toolchain ships a verifier:

```bash
pip install wacz==0.5.0
wacz validate evidence/c-001/<file>.wacz
wacz info     evidence/c-001/<file>.wacz   # shows signed-data integrity
```

A valid WACZ proves: (a) the page bytes were not altered post-capture
and (b) the capturing browser identity (set by Browsertrix).

---

## 6. Verify the gitsign commit (if pushed)

```bash
cd license-watch-evidence
git log --show-signature -1 -- c-001/

# More explicit:
gitsign verify --certificate-identity      "andrew@88plug.com" \
               --certificate-oidc-issuer   "https://token.actions.githubusercontent.com" \
               HEAD
```

The commit's signature is itself anchored in Rekor — a second,
independent transparency log entry covering the entire evidence
directory's tree hash.

---

## 7. Mapping to U.S. Federal Rules of Evidence

| FRE rule | What it requires | How L6 satisfies it |
|---|---|---|
| **901(a)** | Authenticate / identify the item | SHA-256 + SHA-512 + WACZ signed datapackage |
| **901(b)(9)** | Evidence about a process or system | This playbook + reproducible Dockerfile.evidence + open-source code |
| **902(13)** | Self-authenticating records generated by an electronic process | RFC 3161 TSR with valid CA chain |
| **902(14)** | Self-authenticating data copied from electronic device, hash-verified | Multiple independent hashes + transparency-log inclusion proof |

### Proposed FRE 707 (machine-generated evidence Daubert gate)

If FRE 707 is adopted as proposed, machine-generated evidence will
face a **Daubert** reliability gate. L6's design directly maps:

- **Testable / falsifiable**: every step is reproducible from a
  pinned Dockerfile; tampering is detectable by re-hash.
- **Peer review**: TSRs, Rekor, OTS are all RFC- or
  RFC-equivalent-grade public protocols with extensive literature.
- **Error rate**: SHA-256 collision probability ≈ 2⁻¹²⁸ per anchor;
  three independent anchor systems make joint forgery
  computationally infeasible.
- **Standards**: RFC 3161, RFC 5816, IETF SCITT, WACZ 1.0.0.
- **Acceptance**: Sigstore is used in production by Kubernetes,
  npm signing, the Linux Foundation; OTS has French court precedent.

Keep a printout of this section attached to the exhibit.

---

## 8. Quick reference — one-liner full audit

```bash
preserve --verify-bundle ./evidence/c-001/ \
  && echo "INTERNAL OK — proceed to external tool checks"

for tsr in evidence/c-001/*.tsr; do
  openssl ts -verify -in "$tsr" -data "${tsr%.*.tsr}" \
    -CAfile freetsa-cacert.pem 2>&1 | tail -1
done

cosign verify-blob \
  --bundle evidence/c-001/*.cosign.bundle \
  --certificate-identity     "andrew@88plug.com" \
  --certificate-oidc-issuer  "https://token.actions.githubusercontent.com" \
  evidence/c-001/*.wacz

ots upgrade evidence/c-001/*.ots && ots verify evidence/c-001/*.ots
```

All four blocks must succeed for an unimpeachable chain. ONE TSA +
Rekor + OTS is the minimum acceptable subset.

---

## 9. Versions pinned

| Component | Version |
|---|---|
| cosign | v2.4.1 |
| gitsign | v0.12.0 |
| rekor-cli | v1.3.10 |
| opentimestamps-client | 0.7.2 |
| browsertrix-crawler | 1.5.0 |
| playwright | 1.49.0 |
| Go | 1.23.4 |

The `Dockerfile.evidence` reproduces the entire chain.
