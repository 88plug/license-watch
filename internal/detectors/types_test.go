package detectors

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// JSONL schema is the contract with L3. Any field rename = breakage downstream.
func TestCandidateJSONLSchema(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	c := Candidate{
		Source:  "gh_archive",
		URL:     "https://github.com/evil/copy",
		Name:    "intel-amt-linux",
		Snippet: "fork of 88plug/intel-amt-linux",
		TS:      "2026-05-27T10:00:00Z",
		Raw:     json.RawMessage(`{"type":"ForkEvent"}`),
	}
	if err := w.Write(c); err != nil {
		t.Fatalf("write: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("must be single line per record, got %q", buf.String())
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"source", "url", "name", "snippet", "ts", "raw"}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in JSONL output: %s", k, line)
		}
	}
}

func TestWriterAutoTS(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Write(Candidate{Source: "x", URL: "https://example.com", Name: "n"}); err != nil {
		t.Fatal(err)
	}
	var c Candidate
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &c); err != nil {
		t.Fatal(err)
	}
	if c.TS == "" {
		t.Fatal("expected auto-populated TS")
	}
}

func TestWriterMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for i := 0; i < 3; i++ {
		if err := w.Write(Candidate{Source: "x", URL: "u", Name: "n"}); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for _, l := range lines {
		var c Candidate
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatalf("line not valid JSON: %v: %s", err, l)
		}
	}
}

func TestRegistryCount(t *testing.T) {
	all := All()
	if len(all) < 17 {
		t.Fatalf("expected >=17 detectors, got %d", len(all))
	}
	names := map[string]bool{}
	for _, d := range all {
		if names[d.Name()] {
			t.Errorf("duplicate detector name: %s", d.Name())
		}
		names[d.Name()] = true
	}
}

func TestMatchAnyCaseInsensitive(t *testing.T) {
	wl := &Watchlist{Projects: []WatchlistEntry{
		{Name: "intel-amt-linux", DistinctiveStrings: []string{"imrsdk-linux"}},
	}}
	cases := []string{
		"check out intel-amt-linux on github",
		"INTEL-AMT-LINUX rocks",
		"i hate imrsdk-linux",
	}
	for _, c := range cases {
		if MatchAny(c, wl) == nil {
			t.Errorf("expected match for %q", c)
		}
	}
	if MatchAny("totally unrelated text", wl) != nil {
		t.Error("expected no match")
	}
}
