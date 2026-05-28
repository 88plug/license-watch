package detectors

// YouTube Data API v3 — search.list endpoint.
// Docs: https://developers.google.com/youtube/v3/docs/search/list
// Quota: 100 units per search call; 10k units/day default. Throttle 1/s.
// Requires YOUTUBE_API_KEY env var.

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"time"
)

type youtubeDetector struct{ t *Throttle }

func NewYouTube() Detector { return youtubeDetector{t: NewThrottle(1, time.Second)} }
func (youtubeDetector) Name() string { return "youtube" }

type ytResp struct {
	Items []struct {
		ID struct {
			VideoID string `json:"videoId"`
		} `json:"id"`
		Snippet struct {
			Title        string `json:"title"`
			Description  string `json:"description"`
			ChannelTitle string `json:"channelTitle"`
			PublishedAt  string `json:"publishedAt"`
		} `json:"snippet"`
	} `json:"items"`
}

func (d youtubeDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	key := os.Getenv("YOUTUBE_API_KEY")
	if key == "" {
		return "", ErrSkip
	}
	for _, p := range wl.Projects {
		queries := append([]string{p.Name}, p.DistinctiveStrings...)
		for _, q := range queries {
			if q == "" {
				continue
			}
			if err := d.t.Wait(ctx); err != nil {
				return "", err
			}
			var resp ytResp
			u := "https://www.googleapis.com/youtube/v3/search?part=snippet&maxResults=15&type=video&order=date&q=" +
				url.QueryEscape(q) + "&key=" + url.QueryEscape(key)
			if err := GetJSON(ctx, u, nil, &resp); err != nil {
				continue
			}
			for _, it := range resp.Items {
				if it.ID.VideoID == "" {
					continue
				}
				raw, _ := json.Marshal(it)
				out <- Candidate{
					Source:  "youtube",
					URL:     "https://www.youtube.com/watch?v=" + it.ID.VideoID,
					Name:    p.Name,
					Snippet: Snippet(it.Snippet.ChannelTitle+": "+it.Snippet.Title+" — "+it.Snippet.Description, 256),
					TS:      it.Snippet.PublishedAt,
					Raw:     raw,
				}
			}
		}
	}
	return "", nil
}
