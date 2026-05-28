package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Bundler assembles all artifacts under evidence/{candidate-id}/ and
// writes MANIFEST.json. The manifest is the canonical chain-of-custody
// record; everything else exists to support it.
type Bundler struct {
	// Root is the evidence root, typically ./evidence
	Root string
	// Operator identifies the signing identity that ran the capture.
	Operator string
}

// NewBundler returns defaults.
func NewBundler(root, operator string) *Bundler {
	return &Bundler{Root: root, Operator: operator}
}

// Dir returns the evidence directory for a candidate ID, creating
// it if needed. Path: {Root}/{candidate-id}/.
func (b *Bundler) Dir(candidateID string) (string, error) {
	d := filepath.Join(b.Root, candidateID)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

// WriteManifest serializes the manifest and writes both pretty
// MANIFEST.json (human review) and MANIFEST.jsonl (single line,
// stream-friendly per ARCHITECTURE.md "strict JSONL manifests").
func (b *Bundler) WriteManifest(m *Manifest) (jsonPath, jsonlPath string, err error) {
	dir, err := b.Dir(m.CandidateID)
	if err != nil {
		return "", "", err
	}
	pretty, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", "", err
	}
	jsonPath = filepath.Join(dir, "MANIFEST.json")
	if err := os.WriteFile(jsonPath, pretty, 0o644); err != nil {
		return "", "", err
	}
	single, err := json.Marshal(m)
	if err != nil {
		return "", "", err
	}
	jsonlPath = filepath.Join(dir, "MANIFEST.jsonl")
	if err := os.WriteFile(jsonlPath, append(single, '\n'), 0o644); err != nil {
		return "", "", err
	}
	return jsonPath, jsonlPath, nil
}

// AppendTimelineEvent appends a TimelineEvent at the current time.
// Helper for orchestrators.
func AppendTimelineEvent(m *Manifest, step, detail string) {
	m.Timeline = append(m.Timeline, TimelineEvent{
		At:     time.Now().UTC(),
		Step:   step,
		Detail: detail,
	})
}

// Validate runs basic shape checks on a manifest. Returns nil if ok.
func Validate(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest is nil")
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version %q, want %q", m.SchemaVersion, SchemaVersion)
	}
	if m.CandidateID == "" {
		return fmt.Errorf("candidate_id is empty")
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("no artifacts")
	}
	for i, a := range m.Artifacts {
		if a.SHA256 == "" || len(a.SHA256) != 64 {
			return fmt.Errorf("artifact[%d] %s: invalid sha256", i, a.Path)
		}
		if a.SHA512 == "" || len(a.SHA512) != 128 {
			return fmt.Errorf("artifact[%d] %s: invalid sha512", i, a.Path)
		}
	}
	if len(m.Timestamps) < 2 {
		return fmt.Errorf("require >=2 independent TSA timestamps, got %d", len(m.Timestamps))
	}
	return nil
}
