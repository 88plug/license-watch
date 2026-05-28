package detectors

// ecosyste.ms — federates 30+ package registries in one call.
// Docs: https://packages.ecosyste.ms/docs
// Rate limit: 60 req/min documented. Throttle 1/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type ecosystemsDetector struct{ t *Throttle }

func NewEcosystems() Detector  { return ecosystemsDetector{t: NewThrottle(1, time.Second)} }
func (ecosystemsDetector) Name() string { return "ecosystems" }

type ecosystemsHit struct {
	Ecosystem   string `json:"ecosystem"`
	Registry    string `json:"registry"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HomepageURL string `json:"homepage_url"`
	RepositoryURL string `json:"repository_url"`
	UpdatedAt   string `json:"updated_at"`
}

func (d ecosystemsDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		if p.Name == "" {
			continue
		}
		if err := d.t.Wait(ctx); err != nil {
			return "", err
		}
		var hits []ecosystemsHit
		u := "https://packages.ecosyste.ms/api/v1/packages/lookup?name=" + url.QueryEscape(p.Name)
		if err := GetJSON(ctx, u, nil, &hits); err != nil {
			continue
		}
		for _, h := range hits {
			raw, _ := json.Marshal(h)
			pageURL := h.HomepageURL
			if pageURL == "" {
				pageURL = h.RepositoryURL
			}
			out <- Candidate{
				Source:  "ecosystems",
				URL:     pageURL,
				Name:    p.Name,
				Snippet: Snippet(h.Ecosystem+":"+h.Name+" — "+h.Description, 256),
				Raw:     raw,
			}
		}
	}
	return "", nil
}
