// lw-functionsimsearch — thin CLI over internal/structural FSS wrapper.
//
// Usage:
//
//	lw-functionsimsearch --index <path> --binary <path> [--max-dist 32]
//
// Emits one JSON match per line on stdout; logs go to stderr.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	structural "github.com/88plug/license-watch/internal/structural"
)

func main() {
	idx := flag.String("index", "", "path to SimHash search index (built from 88plug refs)")
	bin := flag.String("binary", "", "candidate binary to fingerprint + search")
	maxDist := flag.Int("max-dist", structural.MatchThreshold, "max Hamming distance")
	fpxxBin := flag.String("fpxx-bin", "fingerprintxx", "fingerprintxx binary path")
	indexBin := flag.String("indexsearch-bin", "simhashsearchindex", "simhashsearchindex binary path")
	flag.Parse()

	if *idx == "" || *bin == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := structural.RequireTools(*fpxxBin, *indexBin); err != nil {
		log.Fatalf("missing upstream: %v", err)
	}
	matches, err := structural.SearchIndex(*indexBin, *idx, *bin, *maxDist)
	if err != nil {
		log.Fatalf("search failed: %v", err)
	}
	w := bufio.NewWriter(os.Stdout)
	if err := structural.EmitJSONL(matches, w); err != nil {
		log.Fatalf("emit failed: %v", err)
	}
	fmt.Fprintf(os.Stderr, "matched %d functions\n", len(matches))
}
