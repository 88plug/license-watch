package evidence

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Capturer produces a primary web archive of the suspect URL. The default
// path is Browsertrix Crawler via docker. If Browsertrix is unavailable
// (no docker, no network image pull), we fall back to a raw HTML+screenshot
// pull and submit the URL to the Internet Archive Wayback "Save Page Now"
// endpoint so a second independent archive exists.
type Capturer struct {
	// WorkDir is where artifacts land. Required.
	WorkDir string
	// DockerBin overrides docker path; empty = PATH lookup.
	DockerBin string
	// BrowsertrixImage overrides the pinned image.
	BrowsertrixImage string
	// HTTPClient is used for Wayback fallback + raw HTML pull.
	HTTPClient *http.Client
	// WaybackEnabled toggles the Wayback ping (parallel, best-effort).
	WaybackEnabled bool
}

// NewCapturer returns a Capturer with defaults set.
func NewCapturer(workDir string) *Capturer {
	return &Capturer{
		WorkDir:          workDir,
		DockerBin:        "docker",
		BrowsertrixImage: BrowsertrixImage,
		HTTPClient:       &http.Client{Timeout: 60 * time.Second},
		WaybackEnabled:   true,
	}
}

// CaptureResult bundles the produced files for a single URL capture.
type CaptureResult struct {
	WACZPath     string // empty if Browsertrix unavailable
	HTMLPath     string // raw HTML always produced as fallback evidence
	WaybackURL   string // permalink if Wayback accepted the save
	UsedFallback bool
}

// Capture writes WACZ + raw HTML for url under c.WorkDir. Best-effort:
// returns whatever it managed to produce, plus an aggregated error.
func (c *Capturer) Capture(ctx context.Context, url string) (CaptureResult, error) {
	if err := os.MkdirAll(c.WorkDir, 0o755); err != nil {
		return CaptureResult{}, fmt.Errorf("mkdir workdir: %w", err)
	}

	res := CaptureResult{}

	// Always pull raw HTML — it is independent of docker and gives us a
	// minimal fallback artifact even when everything else fails.
	htmlPath, htmlErr := c.fetchRawHTML(ctx, url)
	if htmlErr == nil {
		res.HTMLPath = htmlPath
	}

	// Try Browsertrix.
	waczPath, brxErr := c.runBrowsertrix(ctx, url)
	if brxErr == nil && waczPath != "" {
		res.WACZPath = waczPath
	} else {
		res.UsedFallback = true
	}

	// Always also ping Wayback — second independent archive.
	if c.WaybackEnabled {
		if w, err := c.saveWayback(ctx, url); err == nil {
			res.WaybackURL = w
		}
	}

	// Only consider it a hard failure if BOTH primary archives missing.
	if res.WACZPath == "" && res.HTMLPath == "" {
		return res, fmt.Errorf("capture failed: browsertrix=%v wayback-only insufficient", brxErr)
	}
	return res, nil
}

func (c *Capturer) fetchRawHTML(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "license-watch/L6 (+https://github.com/88plug/license-watch)")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out := filepath.Join(c.WorkDir, sanitize(url)+".html")
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}
	return out, nil
}

func (c *Capturer) runBrowsertrix(ctx context.Context, url string) (string, error) {
	if c.DockerBin == "" {
		c.DockerBin = "docker"
	}
	if _, err := exec.LookPath(c.DockerBin); err != nil {
		return "", fmt.Errorf("docker not in PATH: %w", err)
	}
	id := sanitize(url)
	args := []string{
		"run", "--rm",
		"-v", c.WorkDir + ":/crawls",
		c.BrowsertrixImage,
		"crawl",
		"--url", url,
		"--generateWACZ",
		"--collection", id,
		"--scopeType", "page",
		"--limit", "1",
	}
	cmd := exec.CommandContext(ctx, c.DockerBin, args...)
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("browsertrix: %w", err)
	}
	// Browsertrix writes /crawls/collections/<id>/<id>.wacz
	wacz := filepath.Join(c.WorkDir, "collections", id, id+".wacz")
	if _, err := os.Stat(wacz); err != nil {
		return "", fmt.Errorf("wacz missing: %w", err)
	}
	return wacz, nil
}

func (c *Capturer) saveWayback(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, WaybackSavePrefix+url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "license-watch/L6")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("wayback status %d", resp.StatusCode)
	}
	// Wayback sets Content-Location to the snapshot path
	if loc := resp.Header.Get("Content-Location"); loc != "" {
		return "https://web.archive.org" + loc, nil
	}
	return WaybackSavePrefix + url, nil
}

// sanitize derives a filesystem-safe identifier from a URL.
func sanitize(s string) string {
	r := strings.NewReplacer(
		"://", "_", "/", "_", "?", "_", "&", "_", "=", "_",
		"#", "_", ":", "_", " ", "_", "\\", "_",
	)
	out := r.Replace(s)
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}
