package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPreserve_EndToEnd_Synthetic runs Preserve against a synthetic
// suspect URL with mocked Browsertrix (replaced by raw HTML pull
// against a local httptest server), mocked TSAs (in-process http
// servers returning canned TSR bytes), and mocked Rekor/OTS via the
// Options hook functions. Asserts the manifest schema and that every
// artifact hash matches the bytes on disk.
func TestPreserve_EndToEnd_Synthetic(t *testing.T) {
	// Synthetic suspect site.
	suspect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>verbatim copy of 88plug LICENSE.md</p></body></html>"))
	}))
	defer suspect.Close()

	// In-process TSA — returns canned bytes (we are not validating
	// CMS signatures here; the verify_test exercises hash invariants).
	tsrPayload := []byte("CANNED-TSR-BYTES-FOR-TEST")
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/timestamp-query" {
			t.Errorf("tsa content-type = %q", got)
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(tsrPayload)
	}))
	defer tsa.Close()

	tmp := t.TempDir()
	opts := &Options{
		WorkRoot: tmp,
		Operator: "test-operator",
		Capturer: &Capturer{
			WorkDir:    tmp,
			DockerBin:  "definitely-not-on-path-docker", // forces fallback
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
			// Don't ping real Wayback during tests.
			WaybackEnabled: false,
		},
		Screenshotter: &Screenshotter{WorkDir: tmp, NodeBin: "definitely-not-on-path-node"},
		TSAs: []*TSAClient{
			{Name: "MockTSA-A", URL: tsa.URL, HTTPClient: tsa.Client()},
			{Name: "MockTSA-B", URL: tsa.URL, HTTPClient: tsa.Client()},
		},
		SignFn: func(ctx context.Context, path string) (*RekorEntry, error) {
			// Fake a Rekor bundle on disk.
			b := []byte(`{"rekorBundle":{"SignedEntryTimestamp":"SET","Payload":{"logIndex":12345,"logID":"abcd","integratedTime":1716700000}}}`)
			bp := path + ".cosign.bundle"
			if err := os.WriteFile(bp, b, 0o644); err != nil {
				return nil, err
			}
			return &RekorEntry{
				UUID:         "deadbeef",
				LogIndex:     12345,
				LogID:        "abcd",
				IntegratedAt: 1716700000,
				SET:          "SET",
				BundlePath:   bp,
				BundleSHA256: SHA256Bytes(b),
			}, nil
		},
		OTSStampFn: func(ctx context.Context, path string) (*OTSAttestation, error) {
			otsBytes := []byte("FAKE-OTS-PAYLOAD")
			otsPath := path + ".ots"
			if err := os.WriteFile(otsPath, otsBytes, 0o644); err != nil {
				return nil, err
			}
			tgt, err := FileSHA256(path)
			if err != nil {
				return nil, err
			}
			return &OTSAttestation{
				OTSPath:          otsPath,
				OTSSHA256:        SHA256Bytes(otsBytes),
				TargetSHA256:     tgt,
				Calendar:         OTSCalendar,
				BitcoinConfirmed: false,
			}, nil
		},
	}

	cand := Candidate{
		ID:          "test-c-001",
		Severity:    "high",
		SuspectURL:  suspect.URL,
		ProjectName: "intel-amt-linux",
		ClauseCited: "FSL-1.1-ALv2 §3.1",
		Action:      "DMCA-prep",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m, err := Preserve(ctx, opts, cand)
	if err != nil {
		t.Fatalf("Preserve: %v", err)
	}
	if m == nil {
		t.Fatal("manifest is nil")
	}

	// Schema.
	if m.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q", m.SchemaVersion)
	}
	if m.CandidateID != cand.ID {
		t.Errorf("candidate_id = %q", m.CandidateID)
	}
	if m.Tool != "license-watch L6" {
		t.Errorf("tool = %q", m.Tool)
	}
	if len(m.Artifacts) == 0 {
		t.Fatal("no artifacts")
	}
	if len(m.Timestamps) < 2 {
		t.Errorf("expected >=2 timestamps, got %d", len(m.Timestamps))
	}
	if m.Rekor == nil || m.Rekor.LogIndex != 12345 {
		t.Errorf("rekor entry missing or wrong: %+v", m.Rekor)
	}
	if m.OTS == nil || m.OTS.OTSSHA256 == "" {
		t.Errorf("ots attestation missing")
	}

	// Hash invariant: every artifact's recorded SHA-256 must match the
	// re-hash of the file on disk.
	for _, a := range m.Artifacts {
		got, err := FileSHA256(a.Path)
		if err != nil {
			t.Errorf("rehash %s: %v", a.Path, err)
			continue
		}
		if got != a.SHA256 {
			t.Errorf("artifact %s: sha256 drift %s != %s", a.Path, got, a.SHA256)
		}
		want := sha256.Sum256(mustRead(t, a.Path))
		if hex.EncodeToString(want[:]) != a.SHA256 {
			t.Errorf("artifact %s: direct sha mismatch", a.Path)
		}
	}

	// Each TSR digest must match SOME artifact's SHA-256.
	for _, ts := range m.Timestamps {
		matched := false
		for _, a := range m.Artifacts {
			if a.SHA256 == ts.Digest {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("tsa %s digest %s not bound to any artifact", ts.TSA, ts.Digest)
		}
	}

	// Manifest must serialize and round-trip.
	bundler := NewBundler(tmp, "test")
	jp, jlp, err := bundler.WriteManifest(m)
	if err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if !strings.HasSuffix(jp, "MANIFEST.json") || !strings.HasSuffix(jlp, "MANIFEST.jsonl") {
		t.Errorf("manifest paths wrong: %s %s", jp, jlp)
	}
	raw := mustRead(t, jp)
	var rt Manifest
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatalf("manifest round-trip: %v", err)
	}
	if rt.CandidateID != cand.ID {
		t.Errorf("round-trip candidate_id = %q", rt.CandidateID)
	}

	// JSONL must be exactly one line.
	jl := string(mustRead(t, jlp))
	if strings.Count(jl, "\n") != 1 {
		t.Errorf("jsonl manifest must be one line + newline, got %d newlines", strings.Count(jl, "\n"))
	}

	// Validate() must pass.
	if err := Validate(m); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// Evidence dir exists.
	dir := filepath.Join(tmp, cand.ID)
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("evidence dir missing: %v", err)
	}
}

func TestBuildRequest_RFC3161Shape(t *testing.T) {
	digest := sha256.Sum256([]byte("hello"))
	der, err := BuildRequest(digest[:], true)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if len(der) < 10 {
		t.Fatalf("DER too short: %d", len(der))
	}
	// First byte is SEQUENCE tag.
	if der[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got 0x%02x", der[0])
	}
}

func TestHashFile_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "x.bin")
	body := []byte("the quick brown fox jumps over the lazy dog")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	s256, s512, n, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if int(n) != len(body) {
		t.Errorf("size = %d, want %d", n, len(body))
	}
	if len(s256) != 64 {
		t.Errorf("sha256 len = %d", len(s256))
	}
	if len(s512) != 128 {
		t.Errorf("sha512 len = %d", len(s512))
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}
