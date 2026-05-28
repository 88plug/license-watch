package detectors

// PyPI — newest packages RSS + per-name Warehouse JSON.
// Docs: https://warehouse.pypa.io/api-reference/feeds.html
//       https://warehouse.pypa.io/api-reference/json.html
// Rate limit: undocumented; we poll RSS once + 1 JSON GET per watch project.
//
// Cursor unused (RSS is bounded to ~40 entries).

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

type pypiDetector struct{}

func NewPyPI() Detector  { return pypiDetector{} }
func (pypiDetector) Name() string { return "pypi" }

type pypiRSS struct {
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
		} `xml:"item"`
	} `xml:"channel"`
}

func (d pypiDetector) Run(ctx context.Context, wl *Watchlist, _ string, out chan<- Candidate) (string, error) {
	body, err := GetText(ctx, "https://pypi.org/rss/updates.xml", nil, 2*1024*1024)
	if err != nil {
		return "", err
	}
	var rss pypiRSS
	if err := xml.Unmarshal([]byte(body), &rss); err != nil {
		return "", err
	}
	for _, it := range rss.Channel.Items {
		hay := it.Title + " " + it.Description
		entry := MatchAny(hay, wl)
		if entry == nil {
			continue
		}
		out <- Candidate{
			Source:  "pypi",
			URL:     it.Link,
			Name:    entry.Name,
			Snippet: Snippet(it.Title+" — "+it.Description, 256),
			TS:      it.PubDate,
		}
	}

	// Per-project Warehouse JSON for direct-name squat detection.
	for _, p := range wl.Projects {
		name := p.Name
		if name == "" {
			continue
		}
		var meta struct {
			Info struct {
				Summary    string `json:"summary"`
				HomePage   string `json:"home_page"`
				PackageURL string `json:"package_url"`
			} `json:"info"`
		}
		url := "https://pypi.org/pypi/" + name + "/json"
		if err := GetJSON(ctx, url, nil, &meta); err != nil {
			continue // 404 = no squat, ok
		}
		out <- Candidate{
			Source:  "pypi",
			URL:     "https://pypi.org/project/" + name + "/",
			Name:    name,
			Snippet: Snippet("direct name match — "+meta.Info.Summary, 256),
		}
	}
	_ = strings.TrimSpace // keep import set; used in other detectors
	_ = fmt.Sprintf
	return "", nil
}
