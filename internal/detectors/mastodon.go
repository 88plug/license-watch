package detectors

// Mastodon — federated search via mastodon.social public v2/search endpoint.
// Docs: https://docs.joinmastodon.org/methods/search/
// Rate limit: 300 req/5min unauthenticated for public-statuses endpoints. 1/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

type mastodonDetector struct{ t *Throttle }

func NewMastodon() Detector  { return mastodonDetector{t: NewThrottle(1, time.Second)} }
func (mastodonDetector) Name() string { return "mastodon" }

type mastodonResp struct {
	Statuses []struct {
		ID         string `json:"id"`
		URL        string `json:"url"`
		Content    string `json:"content"`
		CreatedAt  string `json:"created_at"`
		Account    struct {
			Acct string `json:"acct"`
		} `json:"account"`
	} `json:"statuses"`
}

func (d mastodonDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp mastodonResp
			u := "https://mastodon.social/api/v2/search?type=statuses&limit=20&q=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, s := range resp.Statuses {
				raw, _ := json.Marshal(s)
				out <- Candidate{
					Source:  "mastodon",
					URL:     s.URL,
					Name:    p.Name,
					Snippet: Snippet(s.Account.Acct+": "+stripHTML(s.Content), 256),
					TS:      s.CreatedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}

func stripHTML(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return b.String()
}
