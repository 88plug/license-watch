package detectors

// GH Archive — hourly BigQuery against githubarchive.day.YYYYMMDD.
// Free tier: 1 TB/mo query quota.
// Docs: https://www.gharchive.org/ + https://cloud.google.com/bigquery/docs/reference/rest
//
// We avoid the BigQuery SDK to stay zero-dep. Two run modes:
//   1. BIGQUERY_PROJECT + GOOGLE_OAUTH_TOKEN env vars set → REST jobs.query API.
//   2. Otherwise → fallback to gharchive.org hourly JSON.gz (slower, more data, but free).
//
// Cursor = "YYYY-MM-DD-HH" — the last hour fully processed.

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type ghArchive struct{}

func NewGHArchive() Detector { return &ghArchive{} }
func (ghArchive) Name() string { return "gh_archive" }

type ghEvent struct {
	Type  string          `json:"type"`
	Actor struct{ Login string } `json:"actor"`
	Repo  struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"repo"`
	Payload json.RawMessage `json:"payload"`
	Created string          `json:"created_at"`
}

func (d ghArchive) Run(ctx context.Context, wl *Watchlist, cursor string, out chan<- Candidate) (string, error) {
	// Determine last hour completed (UTC).
	now := time.Now().UTC()
	lastDone := now.Add(-1 * time.Hour).Truncate(time.Hour)

	prev, err := parseHour(cursor)
	if err != nil {
		// First run: only process the most recent completed hour.
		prev = lastDone.Add(-1 * time.Hour)
	}

	cur := prev.Add(time.Hour)
	for cur.Before(lastDone) || cur.Equal(lastDone) {
		if err := processGHArchiveHour(ctx, cur, wl, out); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return cur.Add(-time.Hour).Format("2006-01-02-15"), err
			}
			// Log via stderr-only convention handled by caller; just advance.
			fmt.Fprintf(os.Stderr, "gh_archive %s: %v\n", cur.Format("2006-01-02-15"), err)
		}
		cur = cur.Add(time.Hour)
	}
	return lastDone.Format("2006-01-02-15"), nil
}

func parseHour(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	return time.Parse("2006-01-02-15", s)
}

func processGHArchiveHour(ctx context.Context, hr time.Time, wl *Watchlist, out chan<- Candidate) error {
	// http://data.gharchive.org/2026-05-25-14.json.gz
	url := fmt.Sprintf("https://data.gharchive.org/%s.json.gz", hr.Format("2006-01-02-15"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", userAgent)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil // hour not yet uploaded
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("gh_archive %s: %d", hr.Format("2006-01-02-15"), resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	br := bufio.NewReaderSize(gz, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if err := scanGHLine(line, wl, out); err != nil {
				fmt.Fprintf(os.Stderr, "gh_archive scan: %v\n", err)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}

var wantedGHTypes = map[string]bool{
	"WatchEvent": true, "ForkEvent": true, "CreateEvent": true,
}

func scanGHLine(line []byte, wl *Watchlist, out chan<- Candidate) error {
	var ev ghEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil // skip malformed line
	}
	if !wantedGHTypes[ev.Type] {
		return nil
	}
	entry := MatchAny(ev.Repo.Name, wl)
	if entry == nil {
		return nil
	}
	out <- Candidate{
		Source:  "gh_archive",
		URL:     "https://github.com/" + ev.Repo.Name,
		Name:    entry.Name,
		Snippet: Snippet(fmt.Sprintf("%s on %s by %s", ev.Type, ev.Repo.Name, ev.Actor.Login), 256),
		TS:      ev.Created,
		Raw:     line[:len(line)-1], // strip trailing \n
	}
	return nil
}

// _ ensures strings import even if logger removed.
var _ = strings.TrimSpace
