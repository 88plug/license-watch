// preserve is the L6 orchestrator: reads ONE confirmed-violation
// candidate JSON on stdin, runs the full evidence preservation chain,
// and emits the resulting MANIFEST JSON on stdout.
//
// Usage:
//
//	echo '{"id":"c-001","severity":"high","suspect_url":"...","project_name":"..."}' \
//	  | preserve --root ./evidence --operator "andrew@88plug.com"
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/88plug/license-watch/internal/evidence"
)

func main() {
	root := flag.String("root", "./evidence", "evidence root directory")
	operator := flag.String("operator", "license-watch", "operator identity (recorded in manifest)")
	timeout := flag.Duration("timeout", 30*time.Minute, "overall preservation timeout")
	commit := flag.Bool("commit", false, "gitsign commit + push the evidence directory")
	repo := flag.String("repo", "", "evidence repo working tree (required with --commit)")
	flag.Parse()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("read stdin: %v", err)
	}
	var cand evidence.Candidate
	if err := json.Unmarshal(raw, &cand); err != nil {
		fatal("parse candidate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Trap SIGINT/SIGTERM so we surface partial manifests.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	opts := evidence.DefaultOptions(*root, *operator)
	if *commit {
		if *repo == "" {
			fatal("--commit requires --repo")
		}
		opts.Committer = evidence.NewCommitter(*repo)
	}

	m, err := evidence.Preserve(ctx, opts, cand)
	if err != nil && m == nil {
		fatal("preserve: %v", err)
	}
	if m != nil {
		bundler := evidence.NewBundler(*root, *operator)
		if _, _, werr := bundler.WriteManifest(m); werr != nil {
			fatal("write manifest: %v", werr)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if eerr := enc.Encode(m); eerr != nil {
			fatal("encode manifest: %v", eerr)
		}
	}
	if err != nil {
		// preservation got a manifest but encountered errors; still exit non-zero
		fmt.Fprintf(os.Stderr, "warn: %v\n", err)
		os.Exit(2)
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "preserve: "+f+"\n", a...)
	os.Exit(1)
}
