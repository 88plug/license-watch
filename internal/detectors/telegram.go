package detectors

// Telegram — public channel previews via t.me/s/{channel}.
// No official API for unauth search; we scrape t.me/s/{channel} per configured channel.
// Config via env TELEGRAM_CHANNELS=channel1,channel2 (comma-separated, no @).
// Throttle 1/s. No rate limit documented; t.me is CDN-cached.

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"
)

type telegramDetector struct{ t *Throttle }

func NewTelegram() Detector { return telegramDetector{t: NewThrottle(1, time.Second)} }
func (telegramDetector) Name() string { return "telegram" }

var tgMsgRE = regexp.MustCompile(`(?s)<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>`)
var tgLinkRE = regexp.MustCompile(`data-post="([^"]+)"`)

func (d telegramDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	raw := os.Getenv("TELEGRAM_CHANNELS")
	if raw == "" {
		return "", ErrSkip
	}
	channels := strings.Split(raw, ",")
	for _, ch := range channels {
		ch = strings.TrimSpace(ch)
		if ch == "" {
			continue
		}
		if err := d.t.Wait(ctx); err != nil {
			return "", err
		}
		body, err := GetText(ctx, "https://t.me/s/"+ch, nil, 4*1024*1024)
		if err != nil {
			continue
		}
		posts := tgLinkRE.FindAllStringSubmatch(body, -1)
		texts := tgMsgRE.FindAllStringSubmatch(body, -1)
		n := len(posts)
		if len(texts) < n {
			n = len(texts)
		}
		for i := 0; i < n; i++ {
			text := stripHTML(texts[i][1])
			entry := MatchAny(text, wl)
			if entry == nil {
				continue
			}
			out <- Candidate{
				Source:  "telegram",
				URL:     "https://t.me/" + posts[i][1],
				Name:    entry.Name,
				Snippet: Snippet(text, 256),
				TS:      time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
	return "", nil
}
