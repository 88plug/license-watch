package detectors

// crates.io — Rust registry search.
// Docs: https://crates.io/data-access (require user-agent with contact info)
// Rate limit: 1 req/s per IP per docs; we cap at 1 req/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type cratesDetector struct{ t *Throttle }

func NewCrates() Detector { return cratesDetector{t: NewThrottle(1, time.Second)} }
func (cratesDetector) Name() string { return "crates" }

type cratesResp struct {
	Crates []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Homepage    string `json:"homepage"`
		Repository  string `json:"repository"`
		UpdatedAt   string `json:"updated_at"`
	} `json:"crates"`
}

func (d cratesDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		if p.Name == "" {
			continue
		}
		if err := d.t.Wait(ctx); err != nil {
			return "", err
		}
		var resp cratesResp
		u := "https://crates.io/api/v1/crates?q=" + url.QueryEscape(p.Name) + "&per_page=20"
		if err := GetJSON(ctx, u, map[string]string{
			"user-agent": "license-watch (andrew@88plug.com)",
		}, &resp); err != nil {
			continue
		}
		for _, c := range resp.Crates {
			raw, _ := json.Marshal(c)
			out <- Candidate{
				Source:  "crates",
				URL:     "https://crates.io/crates/" + c.Name,
				Name:    p.Name,
				Snippet: Snippet(c.Name+" — "+c.Description, 256),
				Raw:     raw,
			}
		}
	}
	return "", nil
}
