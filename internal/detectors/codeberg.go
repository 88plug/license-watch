package detectors

// Codeberg — Forgejo API (Gitea-compatible).
// Docs: https://codeberg.org/api/swagger#/repository/repoSearch
// Rate limit: undocumented; throttle 2/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type codebergDetector struct{ t *Throttle }

func NewCodeberg() Detector { return codebergDetector{t: NewThrottle(2, time.Second)} }
func (codebergDetector) Name() string { return "codeberg" }

type cbResp struct {
	Data []struct {
		ID          int    `json:"id"`
		FullName    string `json:"full_name"`
		HTMLURL     string `json:"html_url"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	} `json:"data"`
}

func (d codebergDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp cbResp
			u := "https://codeberg.org/api/v1/repos/search?limit=20&q=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, r := range resp.Data {
				raw, _ := json.Marshal(r)
				out <- Candidate{
					Source:  "codeberg",
					URL:     r.HTMLURL,
					Name:    p.Name,
					Snippet: Snippet(r.FullName+" — "+r.Description, 256),
					TS:      r.UpdatedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
