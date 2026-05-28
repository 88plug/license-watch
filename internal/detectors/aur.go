package detectors

// AUR — Arch User Repository. Per-name RPC v5.
// Docs: https://wiki.archlinux.org/title/Aurweb_RPC_interface
// Rate limit: "be reasonable" — we throttle to 4 req/s.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type aurDetector struct{ t *Throttle }

func NewAUR() Detector { return aurDetector{t: NewThrottle(4, time.Second)} }
func (aurDetector) Name() string { return "aur" }

type aurResp struct {
	ResultCount int             `json:"resultcount"`
	Results     []json.RawMessage `json:"results"`
}

type aurResult struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	URL         string `json:"URL"`
	Maintainer  string `json:"Maintainer"`
	LastModified int64 `json:"LastModified"`
}

func (d aurDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	for _, p := range wl.Projects {
		name := p.AUR
		if name == "" {
			name = p.Name
		}
		if name == "" {
			continue
		}
		if err := d.t.Wait(ctx); err != nil {
			return "", err
		}
		var resp aurResp
		url := "https://aur.archlinux.org/rpc/v5/search/" + name
		if err := GetJSON(ctx, url, nil, &resp); err != nil {
			continue
		}
		for _, raw := range resp.Results {
			var r aurResult
			if err := json.Unmarshal(raw, &r); err != nil {
				continue
			}
			out <- Candidate{
				Source:  "aur",
				URL:     fmt.Sprintf("https://aur.archlinux.org/packages/%s", r.Name),
				Name:    p.Name,
				Snippet: Snippet(r.Name+" — "+r.Description+" (by "+r.Maintainer+")", 256),
				Raw:     raw,
			}
		}
	}
	return "", nil
}
