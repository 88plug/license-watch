// Package detectors fans 17 sources into a uniform Candidate stream for L3.
// Each detector is a self-contained file. Zero non-stdlib deps.
package detectors

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Candidate is one potential violation match. Strict schema — L3 reads JSONL.
type Candidate struct {
	Source  string          `json:"source"`            // "gh_archive" | "npm" | ...
	URL     string          `json:"url"`               // canonical URL of the artifact
	Name    string          `json:"name"`              // matched watchlist project name
	Snippet string          `json:"snippet"`           // <= 512 char excerpt
	TS      string          `json:"ts"`                // RFC3339 UTC
	Raw     json.RawMessage `json:"raw,omitempty"`     // source-specific payload
	Cursor  string          `json:"cursor,omitempty"`  // optional: source's new high-water mark
}

// Detector is the contract every source implements.
type Detector interface {
	Name() string
	// Run reads cursor (may be ""), emits Candidates via out, returns new cursor.
	Run(ctx context.Context, watch *Watchlist, cursor string, out chan<- Candidate) (newCursor string, err error)
}

// WatchlistEntry matches docs/ARCHITECTURE.md §Watchlist format.
type WatchlistEntry struct {
	Name                string   `yaml:"name"`
	GitHub              string   `yaml:"github"`
	AUR                 string   `yaml:"aur"`
	DistinctiveStrings  []string `yaml:"distinctive_strings"`
	LicensePath         string   `yaml:"license_path"`
}

// Watchlist is the top-level watch.yml structure.
type Watchlist struct {
	Projects []WatchlistEntry `yaml:"projects"`
}

// Writer serializes Candidates to JSONL in a goroutine-safe way.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (jw *Writer) Write(c Candidate) error {
	if c.TS == "" {
		c.TS = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	jw.mu.Lock()
	defer jw.mu.Unlock()
	if _, err := jw.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
