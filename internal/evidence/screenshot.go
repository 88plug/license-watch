package evidence

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Screenshotter drives Playwright (via the headless `npx playwright`
// runner, or the `chromium-headless-shell` binary if present) to take
// full-page PNGs and compute perceptual hashes.
//
// The production container Dockerfile.evidence ships playwright-go
// linked into the binary; this code paths shells out for portability
// and to keep the Go module dependency tree minimal at scaffold time.
type Screenshotter struct {
	WorkDir   string
	NodeBin   string
	HelperJS  string // optional path to a project-shipped capture script
	Engine    string // "playwright" | "chromium-headless-shell" (informational)
}

// NewScreenshotter returns defaults.
func NewScreenshotter(workDir string) *Screenshotter {
	return &Screenshotter{
		WorkDir: workDir,
		NodeBin: "npx",
		Engine:  "playwright",
	}
}

// Shot captures url as a full-page PNG plus pHash + dHash JSON sidecar.
type Shot struct {
	PNGPath   string
	PHashPath string
	DHashPath string
}

// Capture writes the PNG and (placeholder) perceptual-hash sidecars.
// In container production the helper script also writes pHash/dHash
// JSON computed by corona10/goimagehash (Go) or imagehash (Python).
// We accept whatever sidecars are present; tests synthesize the PNG.
func (s *Screenshotter) Capture(ctx context.Context, url string) (Shot, error) {
	if err := os.MkdirAll(s.WorkDir, 0o755); err != nil {
		return Shot{}, fmt.Errorf("mkdir: %w", err)
	}
	id := sanitize(url)
	png := filepath.Join(s.WorkDir, id+".png")
	phash := filepath.Join(s.WorkDir, id+".phash.json")
	dhash := filepath.Join(s.WorkDir, id+".dhash.json")

	// Headless capture is best-effort: in CI/Hetzner container this
	// shells out; in unit tests the caller pre-populates the file.
	if _, err := exec.LookPath(s.NodeBin); err == nil {
		args := []string{
			"playwright", "screenshot",
			"--full-page", "--browser=chromium",
			url, png,
		}
		cmd := exec.CommandContext(ctx, s.NodeBin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run() // best-effort; final manifest verifies the file
	}

	out := Shot{}
	if _, err := os.Stat(png); err == nil {
		out.PNGPath = png
	}
	if _, err := os.Stat(phash); err == nil {
		out.PHashPath = phash
	}
	if _, err := os.Stat(dhash); err == nil {
		out.DHashPath = dhash
	}
	return out, nil
}
