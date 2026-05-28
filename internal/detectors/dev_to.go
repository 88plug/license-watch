package detectors

// dev.to — Forem search API.
// Docs: https://developers.forem.com/api/v1#tag/search/operation/searchPosts
// Rate limit: 5 req/s anon. Throttle 3/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type devToDetector struct{ t *Throttle }

func NewDevTo() Detector { return devToDetector{t: NewThrottle(3, time.Second)} }
func (devToDetector) Name() string { return "dev_to" }

type devToResp struct {
	Result []struct {
		Title        string `json:"title"`
		URL          string `json:"url"`
		Path         string `json:"path"`
		Description  string `json:"description"`
		PublishedAt  string `json:"published_at"`
	} `json:"result"`
}

func (d devToDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp devToResp
			u := "https://dev.to/search/feed_content?per_page=20&class_name=Article&search_fields=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, r := range resp.Result {
				raw, _ := json.Marshal(r)
				link := r.URL
				if link == "" {
					link = "https://dev.to" + r.Path
				}
				out <- Candidate{
					Source:  "dev_to",
					URL:     link,
					Name:    p.Name,
					Snippet: Snippet(r.Title+" — "+r.Description, 256),
					TS:      r.PublishedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
