package detectors

// Stack Exchange — federated /2.3/search/excerpts.
// Docs: https://api.stackexchange.com/docs/excerpt-search
// Rate limit: 300 req/day anon; 10000/day with key. Throttle 1/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"time"
)

type stackDetector struct{ t *Throttle }

func NewStackExchange() Detector  { return stackDetector{t: NewThrottle(1, time.Second)} }
func (stackDetector) Name() string { return "stackexchange" }

type stackResp struct {
	Items []struct {
		Title        string   `json:"title"`
		Link         string   `json:"link"`
		Excerpt      string   `json:"excerpt"`
		Tags         []string `json:"tags"`
		CreationDate int64    `json:"creation_date"`
	} `json:"items"`
}

func (d stackDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	keyParam := ""
	if k := os.Getenv("STACKEXCHANGE_KEY"); k != "" {
		keyParam = "&key=" + url.QueryEscape(k)
	}
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			for _, site := range []string{"stackoverflow", "unix", "askubuntu"} {
				if err := d.t.Wait(ctx); err != nil {
					return "", err
				}
				var resp stackResp
				u := "https://api.stackexchange.com/2.3/search/excerpts?site=" + site +
					"&order=desc&sort=creation&pagesize=20&q=" + url.QueryEscape(q) + keyParam
				if err := GetJSON(ctx, u, nil, &resp); err != nil {
					continue
				}
				for _, it := range resp.Items {
					raw, _ := json.Marshal(it)
					out <- Candidate{
						Source:  "stackexchange",
						URL:     it.Link,
						Name:    p.Name,
						Snippet: Snippet(it.Title+" — "+it.Excerpt, 256),
						TS:      time.Unix(it.CreationDate, 0).UTC().Format(time.RFC3339),
						Raw:     raw,
					}
				}
			}
		}
	}
	return "", nil
}
