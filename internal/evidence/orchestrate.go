package evidence

import (
	"context"
	"fmt"
	"time"
)

// Options bundles every replaceable collaborator. Tests inject fakes.
type Options struct {
	WorkRoot string // evidence root, e.g. "./evidence"
	Operator string

	Capturer      *Capturer
	Screenshotter *Screenshotter
	TSAs          []*TSAClient
	Signer        *Signer
	OTS           *OTSClient
	Committer     *Committer // nil => skip git commit (CI path overrides)

	// Hooks let tests stub remote calls without touching network.
	StampFn   func(ctx context.Context, tsa *TSAClient, path string) (Timestamp, error)
	SignFn    func(ctx context.Context, path string) (*RekorEntry, error)
	OTSStampFn func(ctx context.Context, path string) (*OTSAttestation, error)
}

// DefaultOptions returns a production-shaped Options for evidenceRoot.
func DefaultOptions(evidenceRoot, operator string) *Options {
	return &Options{
		WorkRoot: evidenceRoot,
		Operator: operator,
		TSAs:     []*TSAClient{NewFreeTSA(), NewDigicertTSA()},
		Signer:   NewSigner(),
		OTS:      NewOTSClient(),
	}
}

// Preserve runs the full L6 chain against one Candidate and returns
// the final Manifest. Errors at any step are recorded into the
// timeline; the chain continues whenever a later step can still
// add independent evidence.
func Preserve(ctx context.Context, opts *Options, cand Candidate) (*Manifest, error) {
	if opts == nil {
		return nil, fmt.Errorf("opts is nil")
	}
	if cand.ID == "" {
		return nil, fmt.Errorf("candidate id required")
	}

	bundler := NewBundler(opts.WorkRoot, opts.Operator)
	dir, err := bundler.Dir(cand.ID)
	if err != nil {
		return nil, err
	}

	m := &Manifest{
		SchemaVersion: SchemaVersion,
		CandidateID:   cand.ID,
		Candidate:     cand,
		CapturedAt:    time.Now().UTC(),
		Operator:      opts.Operator,
		Tool:          "license-watch L6",
		ToolVersion:   ToolVersion,
	}
	AppendTimelineEvent(m, "begin", "L6 preservation chain start")

	// 1. WACZ + raw HTML capture.
	if opts.Capturer == nil {
		opts.Capturer = NewCapturer(dir)
	} else {
		opts.Capturer.WorkDir = dir
	}
	cap, err := opts.Capturer.Capture(ctx, cand.SuspectURL)
	if err != nil {
		AppendTimelineEvent(m, "capture.error", err.Error())
	} else {
		AppendTimelineEvent(m, "capture.ok", fmt.Sprintf("wacz=%q html=%q wayback=%q", cap.WACZPath, cap.HTMLPath, cap.WaybackURL))
	}
	if cap.WACZPath != "" {
		if a, err := NewArtifact(cap.WACZPath, "wacz", "browsertrix", ""); err == nil {
			m.Artifacts = append(m.Artifacts, a)
		}
	}
	if cap.HTMLPath != "" {
		src := "http"
		if cap.UsedFallback {
			src = "http-fallback"
		}
		if a, err := NewArtifact(cap.HTMLPath, "html", src, cap.WaybackURL); err == nil {
			m.Artifacts = append(m.Artifacts, a)
		}
	}

	// 2. Screenshot + perceptual hashes.
	if opts.Screenshotter == nil {
		opts.Screenshotter = NewScreenshotter(dir)
	} else {
		opts.Screenshotter.WorkDir = dir
	}
	shot, _ := opts.Screenshotter.Capture(ctx, cand.SuspectURL)
	for _, p := range []struct{ Path, Kind string }{
		{shot.PNGPath, "screenshot"},
		{shot.PHashPath, "phash"},
		{shot.DHashPath, "dhash"},
	} {
		if p.Path == "" {
			continue
		}
		if a, err := NewArtifact(p.Path, p.Kind, "playwright", ""); err == nil {
			m.Artifacts = append(m.Artifacts, a)
		}
	}
	AppendTimelineEvent(m, "screenshot.done", fmt.Sprintf("png=%q", shot.PNGPath))

	if len(m.Artifacts) == 0 {
		return m, fmt.Errorf("no primary artifacts captured")
	}

	// 3. RFC 3161 timestamps against EVERY TSA, on EVERY primary artifact.
	for _, art := range m.Artifacts {
		// only timestamp primary captures, not derived hashes/sidecars
		if !isPrimaryKind(art.Kind) {
			continue
		}
		for _, tsa := range opts.TSAs {
			ts, err := stamp(ctx, opts, tsa, art.Path)
			if err != nil {
				AppendTimelineEvent(m, "tsa.error", fmt.Sprintf("%s %s: %v", tsa.Name, art.Path, err))
				continue
			}
			m.Timestamps = append(m.Timestamps, ts)
			if a, err := NewArtifact(ts.TSRPath, "tsr", tsa.Name, art.Path); err == nil {
				m.Artifacts = append(m.Artifacts, a)
			}
			AppendTimelineEvent(m, "tsa.ok", fmt.Sprintf("%s digest=%s", tsa.Name, ts.Digest[:16]))
		}
	}

	// 4. Sigstore Rekor anchor of the manifest's first primary artifact.
	primary := firstPrimary(m.Artifacts)
	if primary != "" {
		entry, err := sign(ctx, opts, primary)
		if err != nil {
			AppendTimelineEvent(m, "rekor.error", err.Error())
		} else {
			m.Rekor = entry
			if a, err := NewArtifact(entry.BundlePath, "rekor", "sigstore", entry.UUID); err == nil {
				m.Artifacts = append(m.Artifacts, a)
			}
			AppendTimelineEvent(m, "rekor.ok", fmt.Sprintf("log_index=%d uuid=%s", entry.LogIndex, entry.UUID))
		}
	}

	// 5. OpenTimestamps Bitcoin anchor of the primary artifact.
	if primary != "" {
		att, err := otsStamp(ctx, opts, primary)
		if err != nil {
			AppendTimelineEvent(m, "ots.error", err.Error())
		} else {
			m.OTS = att
			if a, err := NewArtifact(att.OTSPath, "ots", "opentimestamps", att.Calendar); err == nil {
				m.Artifacts = append(m.Artifacts, a)
			}
			AppendTimelineEvent(m, "ots.ok", "Bitcoin anchor pending confirmation")
		}
	}

	// 6. gitsign + push (if configured).
	if opts.Committer != nil {
		msg := fmt.Sprintf("evidence(%s): %s severity=%s", cand.ID, cand.ProjectName, cand.Severity)
		sha, err := opts.Committer.CommitAndPush(ctx, cand.ID, msg)
		if sha != "" {
			m.GitCommit = sha
			m.GitRemotes = opts.Committer.Remotes
		}
		if err != nil {
			AppendTimelineEvent(m, "git.partial", err.Error())
		} else {
			AppendTimelineEvent(m, "git.ok", sha)
		}
	}

	AppendTimelineEvent(m, "end", "L6 preservation chain complete")
	return m, nil
}

func isPrimaryKind(kind string) bool {
	switch kind {
	case "wacz", "html", "screenshot":
		return true
	}
	return false
}

func firstPrimary(arts []Artifact) string {
	for _, a := range arts {
		if isPrimaryKind(a.Kind) {
			return a.Path
		}
	}
	return ""
}

func stamp(ctx context.Context, opts *Options, tsa *TSAClient, path string) (Timestamp, error) {
	if opts.StampFn != nil {
		return opts.StampFn(ctx, tsa, path)
	}
	return tsa.Stamp(ctx, path)
}

func sign(ctx context.Context, opts *Options, path string) (*RekorEntry, error) {
	if opts.SignFn != nil {
		return opts.SignFn(ctx, path)
	}
	if opts.Signer == nil {
		return nil, fmt.Errorf("no signer configured")
	}
	return opts.Signer.Sign(ctx, path)
}

func otsStamp(ctx context.Context, opts *Options, path string) (*OTSAttestation, error) {
	if opts.OTSStampFn != nil {
		return opts.OTSStampFn(ctx, path)
	}
	if opts.OTS == nil {
		return nil, fmt.Errorf("no ots client configured")
	}
	return opts.OTS.Stamp(ctx, path)
}
