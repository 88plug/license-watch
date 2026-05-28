package detectors

// Hacker News — Algolia search API (no auth, public).
// Docs: https://hn.algolia.com/api
// Rate limit: 10,000 req/h public. Throttle 5/s.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

type hnDetector struct{ t *Throttle }

func NewHN() Detector  { return hnDetector{t: NewThrottle(5, time.Second)} }
func (hnDetector) Name() string { return "hn" }

type hnAlgolia struct {
	Hits []struct {
		ObjectID    string `json:"objectID"`
		Title       string `json:"title"`
		StoryText   string `json:"story_text"`
		CommentText string `json:"comment_text"`
		URL         string `json:"url"`
		CreatedAt   string `json:"created_at"`
	} `json:"hits"`
}

func (d hnDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp hnAlgolia
			u := "https://hn.algolia.com/api/v1/search_by_date?hitsPerPage=30&query=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, h := range resp.Hits {
				raw, _ := json.Marshal(h)
				link := h.URL
				if link == "" {
					link = fmt.Sprintf("https://news.ycombinator.com/item?id=%s", h.ObjectID)
				}
				out <- Candidate{
					Source:  "hn",
					URL:     link,
					Name:    p.Name,
					Snippet: Snippet(h.Title+" "+h.StoryText+" "+h.CommentText, 256),
					TS:      h.CreatedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
