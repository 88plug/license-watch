package detectors

// Hugging Face — models + spaces search.
// Docs: https://huggingface.co/docs/hub/en/api
// Rate limit: undocumented; throttle 2/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type hfDetector struct{ t *Throttle }

func NewHF() Detector { return hfDetector{t: NewThrottle(2, time.Second)} }
func (hfDetector) Name() string { return "hf" }

type hfModel struct {
	ID           string `json:"id"`
	ModelID      string `json:"modelId"`
	Author       string `json:"author"`
	LastModified string `json:"lastModified"`
	Description  string `json:"description"`
}

func (d hfDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			for _, kind := range []string{"models", "spaces"} {
				if err := d.t.Wait(ctx); err != nil {
					return "", err
				}
				var resp []hfModel
				u := "https://huggingface.co/api/" + kind + "?limit=20&search=" + url.QueryEscape(q)
				if err := GetJSON(ctx, u, nil, &resp); err != nil {
					continue
				}
				for _, m := range resp {
					raw, _ := json.Marshal(m)
					id := m.ID
					if id == "" {
						id = m.ModelID
					}
					out <- Candidate{
						Source:  "hf",
						URL:     "https://huggingface.co/" + id,
						Name:    p.Name,
						Snippet: Snippet(kind+" "+id+" — "+m.Description, 256),
						TS:      m.LastModified,
						Raw:     raw,
					}
				}
			}
		}
	}
	return "", nil
}
