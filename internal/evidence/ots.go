package evidence

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// OTSClient wraps the `ots` CLI from python-opentimestamps-client.
//
// `ots stamp <file>` produces <file>.ots, an attestation whose
// commitment will be anchored into the Bitcoin blockchain by one of
// the public calendars (default: alice.btc.calendar.opentimestamps.org).
// Confirmation requires a Bitcoin block (~10 min) plus calendar batch
// rotation (~3-6 hours total). The .ots file is fully self-contained
// — later, anyone with a Bitcoin node + `ots verify` reproduces the
// proof without trusting us, the calendars, or any TSA.
//
// Cited: Paris Judicial Court accepted OpenTimestamps for copyright
// authentication (20 Mar 2025).
type OTSClient struct {
	OTSBin   string
	Calendar string // currently informational; ots uses its config
}

// NewOTSClient returns defaults.
func NewOTSClient() *OTSClient {
	return &OTSClient{OTSBin: "ots", Calendar: OTSCalendar}
}

// Stamp creates <filePath>.ots and returns the attestation record.
// Bitcoin confirmation is asynchronous; later runs of `ots upgrade`
// + `ots verify` move BitcoinConfirmed to true.
func (o *OTSClient) Stamp(ctx context.Context, filePath string) (*OTSAttestation, error) {
	if o.OTSBin == "" {
		o.OTSBin = "ots"
	}
	if _, err := exec.LookPath(o.OTSBin); err != nil {
		return nil, fmt.Errorf("ots not in PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, o.OTSBin, "stamp", filePath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ots stamp: %w", err)
	}
	otsPath := filePath + ".ots"
	if _, err := os.Stat(otsPath); err != nil {
		return nil, fmt.Errorf("ots file missing: %w", err)
	}

	target, err := fileSHA256(filePath)
	if err != nil {
		return nil, err
	}
	otsBytes, err := os.ReadFile(otsPath)
	if err != nil {
		return nil, err
	}
	return &OTSAttestation{
		OTSPath:          otsPath,
		OTSSHA256:        SHA256Bytes(otsBytes),
		TargetSHA256:     target,
		Calendar:         o.Calendar,
		BitcoinConfirmed: false,
		Note:             "Bitcoin block confirmation typically lands ~3-6h after stamp; re-run `ots verify` later.",
	}, nil
}

// Verify runs `ots verify <ots>` and reports whether a Bitcoin
// attestation has materialized.
func (o *OTSClient) Verify(ctx context.Context, otsPath string) (bool, error) {
	cmd := exec.CommandContext(ctx, o.OTSBin, "verify", otsPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Pre-confirmation exit codes are non-zero — surface stderr.
		return false, fmt.Errorf("ots verify: %w: %s", err, string(out))
	}
	// `ots verify` prints "Success! Bitcoin block ..." on confirmation.
	for _, line := range splitLines(string(out)) {
		if hasPrefixFold(line, "Success!") || hasPrefixFold(line, "Bitcoin block") {
			return true, nil
		}
	}
	return false, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func splitLines(s string) []string {
	out := []string{}
	cur := []byte{}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, string(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, s[i])
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if a >= 'A' && a <= 'Z' {
			a += 32
		}
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if a != b {
			return false
		}
	}
	return true
}
