// Package structural — custom osv-scalibr Detector that fingerprints 88plug
// projects' distinctive symbols + strings.
//
// osv-scalibr Detector contract: https://github.com/google/osv-scalibr
//   - Implements detector.Detector
//   - Scans a filesystem (FilesystemRoot) for known string/symbol signatures
//   - Emits Finding{} for any match, which L4 promotes to confirmed.jsonl
//
// Signatures are loaded from `signatures.json` shipped with the binary; each entry:
//
//	{
//	  "project": "intel-amt-linux",
//	  "strings":  ["Native Linux GUI + CLI for Intel AMT", "imrsdk-linux"],
//	  "symbols":  ["AmtSessionStart", "imrsdk_open_session_v2"],
//	  "min_hits": 2
//	}
//
// A project is reported when ≥ min_hits signatures match across the scanned tree.
package structural

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Signature describes a single 88plug project's distinctive markers.
type Signature struct {
	Project string   `json:"project"`
	Strings []string `json:"strings"`
	Symbols []string `json:"symbols"`
	MinHits int      `json:"min_hits"`
}

// Finding is a scalibr-compatible detection record.
type Finding struct {
	Project    string   `json:"project"`
	Path       string   `json:"path"`
	HitStrings []string `json:"hit_strings,omitempty"`
	HitSymbols []string `json:"hit_symbols,omitempty"`
	HitCount   int      `json:"hit_count"`
}

// LoadSignatures reads signatures.json from `path`.
func LoadSignatures(path string) ([]Signature, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load signatures: %w", err)
	}
	var sigs []Signature
	if err := json.Unmarshal(b, &sigs); err != nil {
		return nil, fmt.Errorf("parse signatures: %w", err)
	}
	for i := range sigs {
		if sigs[i].MinHits <= 0 {
			sigs[i].MinHits = 1
		}
	}
	return sigs, nil
}

// Detector is the public osv-scalibr-compatible detector.
type Detector struct {
	Sigs []Signature
}

// Name implements detector.Detector.
func (d *Detector) Name() string { return "lw/88plug-fingerprint" }

// Version implements detector.Detector.
func (d *Detector) Version() int { return 1 }

// Scan walks `root` and returns Findings. Concrete osv-scalibr interface wiring
// happens at the binary's main; this method is exported so tests can call it
// without the full scalibr scanner shell.
func (d *Detector) Scan(ctx context.Context, root string) ([]Finding, error) {
	if d == nil || len(d.Sigs) == 0 {
		return nil, errors.New("detector has no signatures")
	}
	// per-project hit accumulators
	hits := make(map[string]*Finding, len(d.Sigs))
	for _, s := range d.Sigs {
		hits[s.Project] = &Finding{Project: s.Project, Path: root}
	}

	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e.IsDir() {
			base := e.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		// skip huge files; we're string-grepping not parsing
		info, err := e.Info()
		if err != nil || info.Size() > 4<<20 {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		text := string(body)
		for _, s := range d.Sigs {
			for _, needle := range s.Strings {
				if needle != "" && strings.Contains(text, needle) {
					hits[s.Project].HitStrings = append(hits[s.Project].HitStrings, needle)
					hits[s.Project].HitCount++
				}
			}
			for _, sym := range s.Symbols {
				if sym != "" && strings.Contains(text, sym) {
					hits[s.Project].HitSymbols = append(hits[s.Project].HitSymbols, sym)
					hits[s.Project].HitCount++
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var out []Finding
	for _, s := range d.Sigs {
		f := hits[s.Project]
		if f.HitCount >= s.MinHits {
			out = append(out, *f)
		}
	}
	return out, nil
}

// EmitFindingsJSONL writes findings as JSONL.
func EmitFindingsJSONL(findings []Finding, w *bufio.Writer) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return w.Flush()
}
