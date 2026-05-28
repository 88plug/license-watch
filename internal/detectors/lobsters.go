package detectors

// Lobsters — public JSON search.
// Docs: https://lobste.rs/about (search.json supported).
// Rate limit: undocumented; throttle 1/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type lobstersDetector struct{ t *Throttle }

func NewLobsters() Detector { return lobstersDetector{t: NewThrottle(1, time.Second)} }
func (lobstersDetector) Name() string { return "lobsters" }

type lobstersResp []struct {
	ShortID    string `json:"short_id"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	ShortIDURL string `json:"short_id_url"`
	CreatedAt  string `json:"created_at"`
	Description string `json:"description"`
}

func (d lobstersDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp lobstersResp
			u := "https://lobste.rs/search.json?q=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, it := range resp {
				raw, _ := json.Marshal(it)
				out <- Candidate{
					Source:  "lobsters",
					URL:     it.ShortIDURL,
					Name:    p.Name,
					Snippet: Snippet(it.Title+" — "+it.Description, 256),
					TS:      it.CreatedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
