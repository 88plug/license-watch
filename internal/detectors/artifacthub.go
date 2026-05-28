package detectors

// ArtifactHub — Helm/OLM/etc package search.
// Docs: https://artifacthub.io/docs/api/
// Rate limit: 60 req/min anon. Throttle 1/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type artifactHubDetector struct{ t *Throttle }

func NewArtifactHub() Detector { return artifactHubDetector{t: NewThrottle(1, time.Second)} }
func (artifactHubDetector) Name() string { return "artifacthub" }

type ahResp struct {
	Packages []struct {
		PackageID   string `json:"package_id"`
		Name        string `json:"name"`
		NormalizedName string `json:"normalized_name"`
		Description string `json:"description"`
		Repository  struct {
			Name string `json:"name"`
			URL  string `json:"url"`
			Kind int    `json:"kind"`
		} `json:"repository"`
		TS int64 `json:"ts"`
	} `json:"packages"`
}

func (d artifactHubDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp ahResp
			u := "https://artifacthub.io/api/v1/packages/search?limit=20&ts_query_web=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, pkg := range resp.Packages {
				raw, _ := json.Marshal(pkg)
				out <- Candidate{
					Source:  "artifacthub",
					URL:     "https://artifacthub.io/packages/search?ts_query_web=" + url.QueryEscape(pkg.Name),
					Name:    p.Name,
					Snippet: Snippet(pkg.Repository.Name+"/"+pkg.Name+" — "+pkg.Description, 256),
					TS:      time.Unix(pkg.TS, 0).UTC().Format(time.RFC3339),
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
