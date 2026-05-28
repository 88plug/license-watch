package detectors

// Docker Hub — repository search.
// Docs: https://docs.docker.com/docker-hub/api/latest/#tag/repositories
// Rate limit: 100/min for anon. We throttle 1 req/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type dockerHubDetector struct{ t *Throttle }

func NewDockerHub() Detector  { return dockerHubDetector{t: NewThrottle(1, time.Second)} }
func (dockerHubDetector) Name() string { return "docker_hub" }

type dockerHubResp struct {
	Results []struct {
		RepoName    string `json:"repo_name"`
		ShortDesc   string `json:"short_description"`
		StarCount   int    `json:"star_count"`
		PullCount   int    `json:"pull_count"`
		IsOfficial  bool   `json:"is_official"`
	} `json:"results"`
}

func (d dockerHubDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		if p.Name == "" {
			continue
		}
		if err := d.t.Wait(ctx); err != nil {
			return "", err
		}
		var resp dockerHubResp
		u := "https://hub.docker.com/v2/search/repositories/?query=" + url.QueryEscape(p.Name)
		if err := GetJSON(ctx, u, nil, &resp); err != nil {
			continue
		}
		for _, r := range resp.Results {
			raw, _ := json.Marshal(r)
			out <- Candidate{
				Source:  "docker_hub",
				URL:     "https://hub.docker.com/r/" + r.RepoName,
				Name:    p.Name,
				Snippet: Snippet(r.RepoName+" — "+r.ShortDesc, 256),
				Raw:     raw,
			}
		}
	}
	return "", nil
}
