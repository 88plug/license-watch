package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Signer wraps the `cosign sign-blob` CLI to anchor an artifact into
// the Sigstore Rekor transparency log. Keyless signing is used —
// Fulcio issues an ephemeral cert against an OIDC identity (GitHub
// Actions OIDC in CI; gitsign-managed identity on the Hetzner box).
//
// We do NOT embed cosign's Go SDK directly because (a) it imports a
// large dependency tree we want isolated in the container layer, and
// (b) the CLI's `--bundle` output is the official portable format —
// `cosign verify-blob --bundle ...` later anywhere reproduces trust.
type Signer struct {
	CosignBin string // "cosign" by default
	// OIDCIssuer is informational, recorded in the bundle.
	OIDCIssuer string
	// RekorURL overrides the public Rekor (default: https://rekor.sigstore.dev)
	RekorURL string
}

// NewSigner returns defaults.
func NewSigner() *Signer {
	return &Signer{CosignBin: "cosign", RekorURL: "https://rekor.sigstore.dev"}
}

// Sign produces a cosign bundle for filePath at filePath + ".cosign.bundle"
// and parses the Rekor entry metadata out of it.
//
// `cosign sign-blob --yes --bundle out.bundle file` writes a JSON bundle
// containing the SET, log index, and the inclusion proof.
func (s *Signer) Sign(ctx context.Context, filePath string) (*RekorEntry, error) {
	if s.CosignBin == "" {
		s.CosignBin = "cosign"
	}
	if _, err := exec.LookPath(s.CosignBin); err != nil {
		return nil, fmt.Errorf("cosign not in PATH: %w", err)
	}
	bundlePath := filepath.Join(filepath.Dir(filePath), filepath.Base(filePath)+".cosign.bundle")

	args := []string{"sign-blob", "--yes", "--bundle", bundlePath}
	if s.RekorURL != "" {
		args = append(args, "--rekor-url", s.RekorURL)
	}
	args = append(args, filePath)

	cmd := exec.CommandContext(ctx, s.CosignBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cosign sign-blob: %w: %s", err, string(out))
	}

	return ParseCosignBundle(bundlePath)
}

// ParseCosignBundle extracts the Rekor entry from a `cosign sign-blob --bundle`
// JSON output. The bundle schema (cosign v2.x) embeds rekorBundle with
// SignedEntryTimestamp, Payload.logIndex, Payload.logID, Payload.integratedTime.
func ParseCosignBundle(path string) (*RekorEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle struct {
		RekorBundle *struct {
			SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
			Payload              struct {
				LogIndex       int64  `json:"logIndex"`
				LogID          string `json:"logID"`
				IntegratedTime int64  `json:"integratedTime"`
				Body           string `json:"body"` // b64 of canonical entry; UUID derived elsewhere
			} `json:"Payload"`
		} `json:"rekorBundle"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("parse cosign bundle: %w", err)
	}
	entry := &RekorEntry{
		BundlePath:   path,
		BundleSHA256: SHA256Bytes(raw),
	}
	if bundle.RekorBundle != nil {
		entry.LogIndex = bundle.RekorBundle.Payload.LogIndex
		entry.LogID = bundle.RekorBundle.Payload.LogID
		entry.IntegratedAt = bundle.RekorBundle.Payload.IntegratedTime
		entry.SET = bundle.RekorBundle.SignedEntryTimestamp
		// UUID is canonicalized log entry hash — exposed by rekor-cli;
		// we record it best-effort from a co-located <bundle>.uuid sidecar
		// the orchestrator writes after `rekor-cli get`.
		if u, err := os.ReadFile(path + ".uuid"); err == nil {
			entry.UUID = strings.TrimSpace(string(u))
		}
	}
	return entry, nil
}
