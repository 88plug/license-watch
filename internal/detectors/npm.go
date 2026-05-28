package detectors

// npm replicate _changes — continuous feed of package updates.
// Docs: https://github.com/npm/registry/blob/main/docs/follower.md
// Endpoint: https://replicate.npmjs.com/_changes?feed=continuous&since={seq}
// No documented rate limit, but we cap the budget to 90s per run.
//
// Cursor = numeric `seq` from last update_seq seen.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type npmDetector struct{}

func NewNPM() Detector  { return npmDetector{} }
func (npmDetector) Name() string { return "npm" }

type npmChange struct {
	Seq json.RawMessage `json:"seq"`
	ID  string          `json:"id"`
	Doc struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		Keywords    []string               `json:"keywords"`
		DistTags    map[string]string      `json:"dist-tags"`
		Repository  map[string]interface{} `json:"repository"`
	} `json:"doc"`
}

func (d npmDetector) Run(ctx context.Context, wl *Watchlist, cursor string, out chan<- Candidate) (string, error) {
	since := cursor
	if since == "" {
		since = "now"
	}
	// Bounded: stop after 90s or 50000 events, whichever first.
	rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	url := fmt.Sprintf(
		"https://replicate.npmjs.com/_changes?feed=continuous&include_docs=true&since=%s",
		since,
	)
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return cursor, err
	}
	req.Header.Set("user-agent", userAgent)
	resp, err := (&http.Client{Timeout: 0}).Do(req)
	if err != nil {
		// Long-poll timeout is expected; treat as graceful.
		if rctx.Err() != nil {
			return cursor, nil
		}
		return cursor, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return cursor, fmt.Errorf("npm changes: %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	last := cursor
	count := 0
	for sc.Scan() {
		if rctx.Err() != nil {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ch npmChange
		if err := json.Unmarshal([]byte(line), &ch); err != nil {
			continue
		}
		if len(ch.Seq) > 0 {
			last = strings.Trim(string(ch.Seq), `"`)
		}
		count++
		hay := ch.ID + " " + ch.Doc.Name + " " + ch.Doc.Description + " " + strings.Join(ch.Doc.Keywords, " ")
		entry := MatchAny(hay, wl)
		if entry == nil {
			continue
		}
		out <- Candidate{
			Source:  "npm",
			URL:     "https://www.npmjs.com/package/" + ch.Doc.Name,
			Name:    entry.Name,
			Snippet: Snippet(ch.Doc.Description, 256),
			Raw:     json.RawMessage(line),
		}
		if count > 50000 {
			break
		}
	}
	// Guard absurd seq values.
	if _, err := strconv.Atoi(last); err == nil || last == "now" || last == cursor {
		return last, nil
	}
	return last, nil
}
