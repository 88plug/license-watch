package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestVerifyManifest_Clean asserts that a freshly-produced manifest
// passes every offline verification step (re-hash + TSR digest
// binding). External tools (openssl/rekor-cli/ots) are skipped if
// not on PATH — those are exercised in container CI.
func TestVerifyManifest_Clean(t *testing.T) {
	tmp := t.TempDir()
	m := makeSyntheticManifest(t, tmp)
	results, err := VerifyManifest(context.Background(), m)
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	for _, r := range results {
		// External-tool steps may legitimately fail with binaries
		// absent. The pure-Go checks (rehash, tsa) must pass.
		if isInternalStep(r.Step) && !r.OK {
			t.Errorf("internal step failed: %s — %s", r.Step, r.Detail)
		}
	}
}

// TestVerifyManifest_DetectsTampering simulates an adversary editing
// a preserved artifact AFTER the manifest is sealed. Verification
// MUST flag the rehash step as failed.
func TestVerifyManifest_DetectsTampering(t *testing.T) {
	tmp := t.TempDir()
	m := makeSyntheticManifest(t, tmp)

	// Tamper: append a single byte to the first artifact.
	target := m.Artifacts[0].Path
	f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0xff}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	results, err := VerifyManifest(context.Background(), m)
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	tampered := false
	for _, r := range results {
		if r.Step == "rehash "+target && !r.OK {
			tampered = true
			break
		}
	}
	if !tampered {
		t.Fatal("expected rehash to detect tampering")
	}
}

func TestValidate_RejectsBadManifest(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"empty id", func(m *Manifest) { m.CandidateID = "" }},
		{"bad schema", func(m *Manifest) { m.SchemaVersion = "wrong" }},
		{"no artifacts", func(m *Manifest) { m.Artifacts = nil }},
		{"single tsa", func(m *Manifest) { m.Timestamps = m.Timestamps[:1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := makeSyntheticManifest(t, t.TempDir())
			tc.mut(m)
			if err := Validate(m); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
		})
	}
}

// makeSyntheticManifest writes 2 fake artifacts + 2 stubbed
// timestamps with correct hash bindings. No network, no tools.
func makeSyntheticManifest(t *testing.T, tmp string) *Manifest {
	t.Helper()
	dir := filepath.Join(tmp, "c-test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	artifacts := []Artifact{}
	for i, kind := range []string{"html", "screenshot"} {
		p := filepath.Join(dir, kind+".bin")
		body := []byte("body-" + string(rune('A'+i)))
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := NewArtifact(p, kind, "synthetic", "")
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, a)
	}

	// Two TSAs both timestamp artifact[0]; digests bound to its sha256.
	tsrPath := filepath.Join(dir, "ts-a.tsr")
	if err := os.WriteFile(tsrPath, []byte("FAKE-TSR-A"), 0o644); err != nil {
		t.Fatal(err)
	}
	tsrPath2 := filepath.Join(dir, "ts-b.tsr")
	if err := os.WriteFile(tsrPath2, []byte("FAKE-TSR-B"), 0o644); err != nil {
		t.Fatal(err)
	}

	tsa := []Timestamp{
		{TSA: "FreeTSA", URL: FreeTSAURL, Digest: artifacts[0].SHA256, TSRPath: tsrPath, IssuedAt: time.Now().UTC()},
		{TSA: "DigiCert", URL: DigicertURL, Digest: artifacts[0].SHA256, TSRPath: tsrPath2, IssuedAt: time.Now().UTC()},
	}
	// Include the TSR files themselves as artifacts so re-hash sweeps catch tampering.
	a3, err := NewArtifact(tsrPath, "tsr", "FreeTSA", "")
	if err != nil {
		t.Fatal(err)
	}
	a4, err := NewArtifact(tsrPath2, "tsr", "DigiCert", "")
	if err != nil {
		t.Fatal(err)
	}
	artifacts = append(artifacts, a3, a4)

	return &Manifest{
		SchemaVersion: SchemaVersion,
		CandidateID:   "c-test",
		Candidate:     Candidate{ID: "c-test", Severity: "high", SuspectURL: "https://example.invalid"},
		CapturedAt:    time.Now().UTC(),
		Operator:      "test",
		Tool:          "license-watch L6",
		ToolVersion:   ToolVersion,
		Artifacts:     artifacts,
		Timestamps:    tsa,
	}
}

func isInternalStep(s string) bool {
	// Internal = rehash/tsa binding. External tool steps start with
	// "openssl"/"rekor-cli"/"ots".
	if len(s) >= 7 && s[:7] == "openssl" {
		return false
	}
	if len(s) >= 9 && s[:9] == "rekor-cli" {
		return false
	}
	if len(s) >= 3 && s[:3] == "ots" {
		return false
	}
	return true
}
