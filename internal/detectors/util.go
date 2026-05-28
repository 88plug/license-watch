package detectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPClient is the shared client. Short default timeout; long-poll detectors
// build their own with ctx-based deadlines.
var HTTPClient = &http.Client{Timeout: 30 * time.Second}

const userAgent = "license-watch/0.1 (+https://github.com/88plug/license-watch)"

// GetJSON does GET, decodes JSON. Headers map merged on request.
func GetJSON(ctx context.Context, url string, headers map[string]string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", userAgent)
	req.Header.Set("accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %d %s", url, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// GetText fetches body as string with size cap.
func GetText(ctx context.Context, url string, headers map[string]string, cap int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s: %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, cap))
	return string(b), err
}

// Throttle is a leaky-bucket. Use one per source per its documented limit.
type Throttle struct{ ch chan struct{} }

// NewThrottle: n events per per. Documented in each detector's header.
func NewThrottle(n int, per time.Duration) *Throttle {
	t := &Throttle{ch: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		t.ch <- struct{}{}
	}
	go func() {
		tick := time.NewTicker(per / time.Duration(n))
		for range tick.C {
			select {
			case t.ch <- struct{}{}:
			default:
			}
		}
	}()
	return t
}

func (t *Throttle) Wait(ctx context.Context) error {
	if t == nil {
		return nil
	}
	select {
	case <-t.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snippet trims and bounds text for the Snippet column.
func Snippet(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max]
	}
	return s
}

// MatchAny returns the first watchlist entry whose distinctive strings or name
// appear (case-insensitive) in haystack.
func MatchAny(haystack string, wl *Watchlist) *WatchlistEntry {
	lh := strings.ToLower(haystack)
	for i, p := range wl.Projects {
		if strings.Contains(lh, strings.ToLower(p.Name)) {
			return &wl.Projects[i]
		}
		for _, s := range p.DistinctiveStrings {
			if s == "" {
				continue
			}
			if strings.Contains(lh, strings.ToLower(s)) {
				return &wl.Projects[i]
			}
		}
	}
	return nil
}

// ErrSkip — detector skipped (missing creds, disabled, etc).
var ErrSkip = errors.New("detector skipped")
