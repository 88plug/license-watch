// Package evidence implements L6 of license-watch: tamper-evident
// preservation of OSS license violations. Output is admissible under
// U.S. FRE 901(b)(9), 902(13), 902(14). Reference: Paris Judicial Court,
// 20 Mar 2025, accepted OpenTimestamps for copyright authentication.
//
// Triple-anchor chain of custody:
//
//  1. WACZ capture (Browsertrix) — full web archive, signed.
//  2. SHA-256 + SHA-512 of every artifact.
//  3. RFC 3161 timestamps from TWO independent TSAs
//     (freetsa.org + timestamp.digicert.com) — redundant.
//  4. Sigstore Rekor entry via `cosign sign-blob` — transparency log.
//  5. OpenTimestamps .ots — Bitcoin blockchain anchor (~3-6h conf).
//  6. gitsign commit into evidence repo, pushed to >=2 remotes
//     (GitHub origin + Codeberg mirror).
//
// An adversary would need to compromise: both TSAs, the Rekor log,
// the Bitcoin chain, and every git remote — simultaneously.
package evidence

import "time"

// Candidate is the L5 confirmed-violation JSON consumed on stdin
// by cmd/preserve. Minimal surface — only fields L6 actually uses.
type Candidate struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	SuspectURL    string   `json:"suspect_url"`
	SuspectRepo   string   `json:"suspect_repo,omitempty"`
	ProjectName   string   `json:"project_name"`
	ClauseCited   string   `json:"clause_cited,omitempty"`
	Action        string   `json:"recommended_action,omitempty"`
	DraftDMCA     string   `json:"draft_dmca,omitempty"`
	ExtraURLs     []string `json:"extra_urls,omitempty"`
}

// Artifact is one preserved file plus its cryptographic identifiers.
type Artifact struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"` // wacz | screenshot | html | phash | dhash | tsr | rekor | ots
	SHA256  string `json:"sha256"`
	SHA512  string `json:"sha512"`
	Bytes   int64  `json:"bytes"`
	Source  string `json:"source,omitempty"` // e.g. browsertrix | wayback | playwright
	Note    string `json:"note,omitempty"`
}

// Timestamp is one RFC 3161 TSA reply.
type Timestamp struct {
	TSA       string    `json:"tsa"`       // friendly name
	URL       string    `json:"url"`       // endpoint
	Digest    string    `json:"digest"`    // SHA-256 hex of the artifact stamped
	TSRPath   string    `json:"tsr_path"`  // path to .tsr file
	TSRSHA256 string    `json:"tsr_sha256"`
	IssuedAt  time.Time `json:"issued_at"`
}

// RekorEntry records a Sigstore transparency-log inclusion.
type RekorEntry struct {
	UUID         string `json:"uuid"`          // log entry UUID
	LogIndex     int64  `json:"log_index"`
	LogID        string `json:"log_id"`
	IntegratedAt int64  `json:"integrated_at"` // unix
	SET          string `json:"set"`           // signed-entry-timestamp (b64)
	BundlePath   string `json:"bundle_path"`   // local cosign bundle
	BundleSHA256 string `json:"bundle_sha256"`
}

// OTSAttestation is the OpenTimestamps Bitcoin anchor.
type OTSAttestation struct {
	OTSPath          string `json:"ots_path"`
	OTSSHA256        string `json:"ots_sha256"`
	TargetSHA256     string `json:"target_sha256"`
	Calendar         string `json:"calendar"` // alice.btc.calendar.opentimestamps.org
	BitcoinConfirmed bool   `json:"bitcoin_confirmed"`
	Note             string `json:"note,omitempty"` // typical ~3-6h latency before block conf
}

// Manifest is the chain-of-custody record. Written as MANIFEST.json
// at the root of evidence/{candidate-id}/ and emitted on stdout.
type Manifest struct {
	SchemaVersion string           `json:"schema_version"`
	CandidateID   string           `json:"candidate_id"`
	Candidate     Candidate        `json:"candidate"`
	CapturedAt    time.Time        `json:"captured_at"`
	Operator      string           `json:"operator"` // identity that ran capture
	Tool          string           `json:"tool"`     // "license-watch L6"
	ToolVersion   string           `json:"tool_version"`
	Artifacts     []Artifact       `json:"artifacts"`
	Timestamps    []Timestamp      `json:"timestamps"`
	Rekor         *RekorEntry      `json:"rekor,omitempty"`
	OTS           *OTSAttestation  `json:"ots,omitempty"`
	GitCommit     string           `json:"git_commit,omitempty"`
	GitRemotes    []string         `json:"git_remotes,omitempty"`
	Timeline      []TimelineEvent  `json:"timeline"`
}

// TimelineEvent is one ordered step in the chain of custody.
type TimelineEvent struct {
	At      time.Time `json:"at"`
	Step    string    `json:"step"`
	Detail  string    `json:"detail,omitempty"`
}

const (
	SchemaVersion = "license-watch/evidence/v1"
	ToolVersion   = "L6-0.1.0"

	FreeTSAURL  = "https://freetsa.org/tsr"
	DigicertURL = "http://timestamp.digicert.com"

	OTSCalendar = "https://alice.btc.calendar.opentimestamps.org"

	BrowsertrixImage = "webrecorder/browsertrix-crawler:1.5.0"
	WaybackSavePrefix = "https://web.archive.org/save/"
)
