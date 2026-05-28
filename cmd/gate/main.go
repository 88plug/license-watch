// gate is the L7 CLI. Reads an L5 verdict JSON file and emits a disposition.
//
// Usage:
//
//	gate --verdict path/to/verdict.json \
//	     --repo 88plug/license-watch \
//	     --dispositions ./dispositions.jsonl \
//	     --drafts-dir ./drafts
//
// Never submits a DMCA. Only drafts + opens a GitHub issue for human review.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/88plug/license-watch/internal/gate"
)

func main() {
	verdictPath := flag.String("verdict", "", "path to L5 verdict JSON (required)")
	repo := flag.String("repo", "88plug/license-watch", "owner/repo to open issues in")
	disp := flag.String("dispositions", "dispositions.jsonl", "append-only audit log path")
	drafts := flag.String("drafts-dir", "drafts", "directory for rendered DMCA / C&D drafts")
	dryRun := flag.Bool("dry-run", false, "do not open a GitHub issue; print decision only")
	flag.Parse()

	if *verdictPath == "" {
		log.Fatal("--verdict is required")
	}
	f, err := os.Open(*verdictPath)
	if err != nil {
		log.Fatalf("open verdict: %v", err)
	}
	defer f.Close()
	v, err := gate.LoadVerdict(f)
	if err != nil {
		log.Fatalf("load verdict: %v", err)
	}

	cfg := gate.Config{
		Repo:             *repo,
		DispositionsPath: *disp,
		DraftsDir:        *drafts,
	}
	if !*dryRun {
		cfg.IssueOpener = &gate.GitHubIssueOpener{}
	}
	g, err := gate.New(cfg)
	if err != nil {
		log.Fatalf("init gate: %v", err)
	}
	d, err := g.Decide(context.Background(), v)
	if err != nil {
		log.Fatalf("decide: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(d); err != nil {
		log.Fatalf("encode disposition: %v", err)
	}
	if d.Error != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", d.Error)
		os.Exit(2)
	}
}
