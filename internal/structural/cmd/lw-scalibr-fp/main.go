// lw-scalibr-fp — CLI front-end for the 88plug scalibr Detector.
//
// Usage:  lw-scalibr-fp --signatures signatures.json --root /path/to/candidate
//
// Emits one Finding JSON per line on stdout.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	structural "github.com/88plug/license-watch/internal/structural"
)

func main() {
	sigPath := flag.String("signatures", "", "path to signatures.json")
	root := flag.String("root", "", "filesystem root to scan")
	flag.Parse()

	if *sigPath == "" || *root == "" {
		flag.Usage()
		os.Exit(2)
	}
	sigs, err := structural.LoadSignatures(*sigPath)
	if err != nil {
		log.Fatalf("signatures: %v", err)
	}
	d := &structural.Detector{Sigs: sigs}
	findings, err := d.Scan(context.Background(), *root)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	w := bufio.NewWriter(os.Stdout)
	if err := structural.EmitFindingsJSONL(findings, w); err != nil {
		log.Fatalf("emit: %v", err)
	}
	fmt.Fprintf(os.Stderr, "scalibr findings: %d\n", len(findings))
}
