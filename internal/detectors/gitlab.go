package detectors

// GitLab — public projects search.
// Docs: https://docs.gitlab.com/ee/api/search.html
// Rate limit: 2000 req/min authenticated; 600/min anon. Throttle 5/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"time"
)

type gitlabDetector struct{ t *Throttle }

func NewGitLab() Detector { return gitlabDetector{t: NewThrottle(5, time.Second)} }
func (gitlabDetector) Name() string { return "gitlab" }

type glProject struct {
	ID          int    `json:"id"`
	PathWithNS  string `json:"path_with_namespace"`
	WebURL      string `json:"web_url"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	LastActivityAt string `json:"last_activity_at"`
}

func (d gitlabDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	headers := map[string]string{}
	if t := os.Getenv("GITLAB_TOKEN"); t != "" {
		headers["private-token"] = t
	}
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp []glProject
			u := "https://gitlab.com/api/v4/projects?per_page=20&order_by=created_at&search=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, headers, &resp); err != nil {
				continue
			}
			for _, pr := range resp {
				raw, _ := json.Marshal(pr)
				out <- Candidate{
					Source:  "gitlab",
					URL:     pr.WebURL,
					Name:    p.Name,
					Snippet: Snippet(pr.PathWithNS+" — "+pr.Description, 256),
					TS:      pr.LastActivityAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
