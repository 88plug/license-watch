// Package structural wraps Google Project Zero's FunctionSimSearch for binary-level
// function similarity matching. Used by L4 against `-bin` packages.
//
// FunctionSimSearch is C++ (https://github.com/googleprojectzero/functionsimsearch);
// this Go file is a thin subprocess wrapper that:
//  1. invokes `fingerprintxx <binary>` to compute SimHash fingerprints
//  2. invokes `simhashsearchindex` against a pre-built index of 88plug binaries
//  3. emits matches over a Hamming-distance threshold
//
// Build:  go build -o bin/lw-functionsimsearch ./internal/structural
// Binary tools (`fingerprintxx`, `simhashsearchindex`, `dotgraphs`, etc.) are built
// from upstream in the Docker image.
package structural

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// MatchThreshold — bits-different threshold for "same function". FunctionSimSearch
// SimHash is 128-bit; ≤32 bits different ≈ strong match (Google's empirical default).
const MatchThreshold = 32

// FSSMatch is one candidate-function ↔ reference-function pair.
type FSSMatch struct {
	CandidatePath    string `json:"candidate_path"`
	CandidateAddress string `json:"candidate_address"`
	ReferenceID      string `json:"reference_id"`
	HammingDistance  int    `json:"hamming_distance"`
}

// FingerprintBinary runs `fingerprintxx` over `path`. Returns address → 128-bit hash hex.
func FingerprintBinary(fpxxBin, path string) (map[string]string, error) {
	cmd := exec.Command(fpxxBin, path)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("fingerprintxx %s: %w", path, err)
	}
	res := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		// upstream format: "<address>\t<simhash_hex>"
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		res[parts[0]] = parts[1]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// SearchIndex runs `simhashsearchindex <index> <binary>` and returns matches.
// Index is a pre-built file containing reference SimHashes (one per 88plug function).
func SearchIndex(indexBin, indexPath, binaryPath string, maxDist int) ([]FSSMatch, error) {
	if maxDist <= 0 {
		maxDist = MatchThreshold
	}
	cmd := exec.Command(indexBin, indexPath, binaryPath, strconv.Itoa(maxDist))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("simhashsearchindex: %w", err)
	}
	var matches []FSSMatch
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// upstream format: "<cand_addr>\t<ref_id>\t<hamming>"
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		d, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		matches = append(matches, FSSMatch{
			CandidatePath:    binaryPath,
			CandidateAddress: parts[0],
			ReferenceID:      parts[1],
			HammingDistance:  d,
		})
	}
	return matches, sc.Err()
}

// EmitJSONL writes one JSON object per FSSMatch to w (caller-provided writer).
// Used by the structural.py orchestrator over `lw-functionsimsearch` subprocess.
func EmitJSONL(matches []FSSMatch, w *bufio.Writer) error {
	enc := json.NewEncoder(w)
	for _, m := range matches {
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ErrToolMissing is returned by RequireTools when an upstream binary is absent.
var ErrToolMissing = errors.New("functionsimsearch upstream tool missing")

// RequireTools verifies the listed binaries exist on PATH or at the given paths.
func RequireTools(paths ...string) error {
	for _, p := range paths {
		if _, err := exec.LookPath(p); err != nil {
			return fmt.Errorf("%w: %s", ErrToolMissing, p)
		}
	}
	return nil
}
