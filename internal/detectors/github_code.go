package detectors

// GitHub code search via `gh api search/code`.
// Docs: https://docs.github.com/en/rest/search/search#search-code
// Rate limit: 30 req/min authenticated. We throttle 30/min.
// Requires GH_TOKEN env var.

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"time"
)

type githubCodeDetector struct{ t *Throttle }

func NewGitHubCode() Detector { return githubCodeDetector{t: NewThrottle(30, time.Minute)} }
func (githubCodeDetector) Name() string { return "github_code" }

type ghCodeResp struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"items"`
}

func (d githubCodeDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	tok := os.Getenv("GH_TOKEN")
	if tok == "" {
		return "", ErrSkip
	}
	headers := map[string]string{
		"authorization": "Bearer " + tok,
		"accept":        "application/vnd.github+json",
		"x-github-api-version": "2022-11-28",
	}
	for _, p := range wl.Projects {
		for _, q := range p.DistinctiveStrings {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp ghCodeResp
			u := "https://api.github.com/search/code?per_page=20&q=" + url.QueryEscape(`"`+q+`"`)
			if err := GetJSON(ctx, u, headers, &resp); err != nil {
				continue
			}
			for _, it := range resp.Items {
				// Skip self matches.
				if it.Repository.FullName == p.GitHub {
					continue
				}
				raw, _ := json.Marshal(it)
				out <- Candidate{
					Source:  "github_code",
					URL:     it.HTMLURL,
					Name:    p.Name,
					Snippet: Snippet(it.Repository.FullName+"/"+it.Path+" matches "+q, 256),
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
