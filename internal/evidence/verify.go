package evidence

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// VerifyResult is a per-step audit outcome.
type VerifyResult struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// VerifyManifest re-runs every check that a court / DMCA reviewer
// would run: re-hash every artifact, confirm TSR digests match,
// optionally exec openssl / rekor-cli / ots if available.
//
// External-tool checks are best-effort: missing binary => SKIP, not
// FAIL. The hash chain alone is sufficient to detect tampering of
// archived evidence.
func VerifyManifest(ctx context.Context, m *Manifest) ([]VerifyResult, error) {
	if err := Validate(m); err != nil {
		return nil, err
	}
	out := []VerifyResult{}

	// 1. Re-hash every artifact.
	for _, a := range m.Artifacts {
		s256, s512, _, err := HashFile(a.Path)
		if err != nil {
			out = append(out, VerifyResult{Step: "rehash " + a.Path, OK: false, Detail: err.Error()})
			continue
		}
		if s256 != a.SHA256 {
			out = append(out, VerifyResult{Step: "rehash " + a.Path, OK: false, Detail: "sha256 mismatch"})
			continue
		}
		if s512 != a.SHA512 {
			out = append(out, VerifyResult{Step: "rehash " + a.Path, OK: false, Detail: "sha512 mismatch"})
			continue
		}
		out = append(out, VerifyResult{Step: "rehash " + a.Path, OK: true})
	}

	// 2. Confirm each Timestamp's digest matches some artifact.
	for _, ts := range m.Timestamps {
		matched := false
		for _, a := range m.Artifacts {
			if a.SHA256 == ts.Digest {
				matched = true
				break
			}
		}
		out = append(out, VerifyResult{
			Step:   fmt.Sprintf("tsa %s", ts.TSA),
			OK:     matched,
			Detail: ts.Digest,
		})
	}

	// 3. Optional: openssl ts -verify.
	if _, err := exec.LookPath("openssl"); err == nil {
		for _, ts := range m.Timestamps {
			cmd := exec.CommandContext(ctx, "openssl", "ts", "-verify",
				"-in", ts.TSRPath, "-digest", ts.Digest)
			if err := cmd.Run(); err != nil {
				out = append(out, VerifyResult{Step: "openssl ts -verify " + ts.TSA, OK: false, Detail: err.Error()})
			} else {
				out = append(out, VerifyResult{Step: "openssl ts -verify " + ts.TSA, OK: true})
			}
		}
	}

	// 4. Optional: rekor-cli inclusion proof.
	if m.Rekor != nil && m.Rekor.UUID != "" {
		if _, err := exec.LookPath("rekor-cli"); err == nil {
			cmd := exec.CommandContext(ctx, "rekor-cli", "get", "--uuid", m.Rekor.UUID)
			if err := cmd.Run(); err != nil {
				out = append(out, VerifyResult{Step: "rekor-cli get", OK: false, Detail: err.Error()})
			} else {
				out = append(out, VerifyResult{Step: "rekor-cli get", OK: true})
			}
		}
	}

	// 5. Optional: ots verify (Bitcoin confirmation, may be pending).
	if m.OTS != nil {
		if _, err := exec.LookPath("ots"); err == nil {
			cmd := exec.CommandContext(ctx, "ots", "verify", m.OTS.OTSPath)
			if err := cmd.Run(); err != nil {
				out = append(out, VerifyResult{Step: "ots verify", OK: false, Detail: "pending Bitcoin confirmation"})
			} else {
				out = append(out, VerifyResult{Step: "ots verify", OK: true})
			}
		}
	}

	return out, nil
}

// fileSHA256/512 helpers exported for cmd/preserve.

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FileSHA512 returns the hex SHA-512 of a file.
func FileSHA512(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
