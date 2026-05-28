package detectors

// Reddit — OAuth-only search since 2023.
// Docs: https://www.reddit.com/dev/api#GET_search
// Rate limit: 100 req/min authenticated; 10/min anon (and degraded). 1 req/s.
// Requires REDDIT_CLIENT_ID + REDDIT_CLIENT_SECRET env.
// We use client_credentials grant (no user account needed).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type redditDetector struct {
	t      *Throttle
	once   sync.Once
	token  string
	tokErr error
}

func NewReddit() Detector  { return &redditDetector{t: NewThrottle(60, time.Minute)} }
func (*redditDetector) Name() string { return "reddit" }

func (r *redditDetector) auth(ctx context.Context) (string, error) {
	r.once.Do(func() {
		id := os.Getenv("REDDIT_CLIENT_ID")
		sec := os.Getenv("REDDIT_CLIENT_SECRET")
		if id == "" || sec == "" {
			r.tokErr = ErrSkip
			return
		}
		body := strings.NewReader("grant_type=client_credentials")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://www.reddit.com/api/v1/access_token", body)
		if err != nil {
			r.tokErr = err
			return
		}
		req.SetBasicAuth(id, sec)
		req.Header.Set("user-agent", userAgent)
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
		resp, err := HTTPClient.Do(req)
		if err != nil {
			r.tokErr = err
			return
		}
		defer resp.Body.Close()
		var tk struct {
			AccessToken string `json:"access_token"`
			Err         string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil {
			r.tokErr = err
			return
		}
		if tk.AccessToken == "" {
			r.tokErr = fmt.Errorf("reddit auth: %s", tk.Err)
			return
		}
		r.token = tk.AccessToken
	})
	return r.token, r.tokErr
}

type redditSearchResp struct {
	Data struct {
		Children []struct {
			Data struct {
				Title       string  `json:"title"`
				Permalink   string  `json:"permalink"`
				URL         string  `json:"url"`
				Subreddit   string  `json:"subreddit"`
				CreatedUTC  float64 `json:"created_utc"`
				SelfText    string  `json:"selftext"`
			} `json:"data"`
		} `json:"children"`
	} `json:"data"`
}

func (r *redditDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	tok, err := r.auth(ctx)
	if err != nil {
		return "", err
	}
	headers := map[string]string{
		"authorization": "Bearer " + tok,
		"user-agent":    userAgent,
	}
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := r.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp redditSearchResp
			u := "https://oauth.reddit.com/search?limit=25&sort=new&q=" + url.QueryEscape(q)
			if err := GetJSON(ctx, u, headers, &resp); err != nil {
				continue
			}
			for _, c := range resp.Data.Children {
				raw, _ := json.Marshal(c.Data)
				out <- Candidate{
					Source:  "reddit",
					URL:     "https://reddit.com" + c.Data.Permalink,
					Name:    p.Name,
					Snippet: Snippet(c.Data.Title+" — "+c.Data.SelfText, 256),
					TS:      time.Unix(int64(c.Data.CreatedUTC), 0).UTC().Format(time.RFC3339),
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
