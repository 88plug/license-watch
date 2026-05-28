package detectors

// Bluesky — AT Protocol public search (no auth required for search).
// Docs: https://docs.bsky.app/docs/api/app-bsky-feed-search-posts
// Rate limit: 3000 req/5min unauthenticated. Throttle 5/s.

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

type blueskyDetector struct{ t *Throttle }

func NewBluesky() Detector  { return blueskyDetector{t: NewThrottle(5, time.Second)} }
func (blueskyDetector) Name() string { return "bluesky" }

type bskyResp struct {
	Posts []struct {
		URI    string `json:"uri"`
		CID    string `json:"cid"`
		Author struct {
			Handle string `json:"handle"`
		} `json:"author"`
		Record struct {
			Text      string `json:"text"`
			CreatedAt string `json:"createdAt"`
		} `json:"record"`
	} `json:"posts"`
}

func (d blueskyDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp bskyResp
			u := "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?limit=25&q=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, post := range resp.Posts {
				raw, _ := json.Marshal(post)
				// at://did:.../app.bsky.feed.post/{rkey} → https://bsky.app/profile/{handle}/post/{rkey}
				webURL := bskyWebURL(post.URI, post.Author.Handle)
				out <- Candidate{
					Source:  "bluesky",
					URL:     webURL,
					Name:    p.Name,
					Snippet: Snippet(post.Author.Handle+": "+post.Record.Text, 256),
					TS:      post.Record.CreatedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}

func bskyWebURL(atURI, handle string) string {
	// at://did/coll/rkey → split, take last segment
	if len(atURI) < 5 {
		return atURI
	}
	parts := splitN(atURI, '/', -1)
	rkey := parts[len(parts)-1]
	return "https://bsky.app/profile/" + handle + "/post/" + rkey
}

func splitN(s string, sep rune, n int) []string {
	out := []string{}
	cur := ""
	count := 0
	for _, r := range s {
		if r == sep && (n < 0 || count < n-1) {
			out = append(out, cur)
			cur = ""
			count++
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
