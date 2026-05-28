// Command detect runs all detectors against watch.yml and emits candidates.jsonl.
//
// Flags:
//   --watch       path to watch.yml (default: watch.yml)
//   --cursors     path to cursors-in.json (optional; missing = "" per source)
//   --cursors-out path to write cursors-out.json (optional)
//   --out         path to candidates.jsonl (default: candidates.jsonl)
//   --timeout     per-detector timeout (default: 120s)
//   --only        comma-separated detector names to run (default: all)
//
// Idempotency: cursors persist last-seen high-water marks so reruns don't
// re-emit the same candidates. Logs go to stderr; stdout reserved for JSONL
// when --out=-.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/88plug/license-watch/internal/detectors"
)

func main() {
	watchPath := flag.String("watch", "watch.yml", "path to watch.yml")
	cursorsIn := flag.String("cursors", "", "path to cursors-in.json (optional)")
	cursorsOut := flag.String("cursors-out", "", "path to cursors-out.json (optional)")
	outPath := flag.String("out", "candidates.jsonl", "path to candidates.jsonl ('-' for stdout)")
	timeout := flag.Duration("timeout", 120*time.Second, "per-detector timeout")
	only := flag.String("only", "", "comma-separated detector names (default all)")
	flag.Parse()

	if err := run(*watchPath, *cursorsIn, *cursorsOut, *outPath, *timeout, *only); err != nil {
		fmt.Fprintf(os.Stderr, "detect: %v\n", err)
		os.Exit(1)
	}
}

func run(watchPath, cursorsInPath, cursorsOutPath, outPath string, timeout time.Duration, only string) error {
	// Load watchlist
	wf, err := os.Open(watchPath)
	if err != nil {
		return fmt.Errorf("open watchlist: %w", err)
	}
	defer wf.Close()
	wl, err := detectors.LoadWatchlist(wf)
	if err != nil {
		return fmt.Errorf("parse watchlist: %w", err)
	}
	if len(wl.Projects) == 0 {
		return errors.New("watchlist is empty")
	}

	// Load cursors-in
	cursorsIn := map[string]string{}
	if cursorsInPath != "" {
		if f, err := os.Open(cursorsInPath); err == nil {
			_ = json.NewDecoder(f).Decode(&cursorsIn)
			f.Close()
		}
	}

	// Open output sink
	var sink io.Writer
	if outPath == "-" {
		sink = os.Stdout
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create out: %w", err)
		}
		defer f.Close()
		sink = f
	}
	jw := detectors.NewWriter(sink)

	// Filter detectors
	wanted := map[string]bool{}
	for _, n := range strings.Split(only, ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			wanted[n] = true
		}
	}

	all := detectors.All()
	cursorsOut := map[string]string{}
	var cursorsMu sync.Mutex
	seen := map[string]bool{}
	var seenMu sync.Mutex

	ch := make(chan detectors.Candidate, 1024)
	var writeWG sync.WaitGroup
	writeWG.Add(1)
	go func() {
		defer writeWG.Done()
		for c := range ch {
			if c.URL == "" {
				continue
			}
			key := c.Source + "|" + c.URL
			seenMu.Lock()
			if seen[key] {
				seenMu.Unlock()
				continue
			}
			seen[key] = true
			seenMu.Unlock()
			if err := jw.Write(c); err != nil {
				fmt.Fprintf(os.Stderr, "write: %v\n", err)
			}
		}
	}()

	var detWG sync.WaitGroup
	ctx := context.Background()
	for _, d := range all {
		if len(wanted) > 0 && !wanted[d.Name()] {
			continue
		}
		detWG.Add(1)
		go func(d detectors.Detector) {
			defer detWG.Done()
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			newCursor, err := d.Run(dctx, wl, cursorsIn[d.Name()], ch)
			dur := time.Since(start).Round(time.Millisecond)
			if err != nil {
				if errors.Is(err, detectors.ErrSkip) {
					fmt.Fprintf(os.Stderr, "skip %s (missing creds)\n", d.Name())
				} else {
					fmt.Fprintf(os.Stderr, "err %s after %s: %v\n", d.Name(), dur, err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "ok %s in %s\n", d.Name(), dur)
			}
			cursorsMu.Lock()
			if newCursor != "" {
				cursorsOut[d.Name()] = newCursor
			} else if v, ok := cursorsIn[d.Name()]; ok {
				cursorsOut[d.Name()] = v
			}
			cursorsMu.Unlock()
		}(d)
	}
	detWG.Wait()
	close(ch)
	writeWG.Wait()

	if cursorsOutPath != "" {
		f, err := os.Create(cursorsOutPath)
		if err != nil {
			return fmt.Errorf("create cursors-out: %w", err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cursorsOut); err != nil {
			return err
		}
	}
	return nil
}
