package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// GitHubIssueOpener creates issues via the REST API.
// It expects a token in $GITHUB_TOKEN (or set Token directly).
// Caller must run the resulting issue submission manually — this only
// drafts and tracks for the human reviewer; it is NOT a DMCA submission.
type GitHubIssueOpener struct {
	Token   string        // PAT or installation token; falls back to $GITHUB_TOKEN
	APIBase string        // default "https://api.github.com"
	HTTP    *http.Client  // default 30s client
	Timeout time.Duration // default 30s
}

// OpenIssue posts to POST /repos/{owner}/{repo}/issues.
// Returns (html_url, number, err).
func (g *GitHubIssueOpener) OpenIssue(ctx context.Context, repo, title, body string, labels []string) (string, int, error) {
	if repo == "" {
		return "", 0, fmt.Errorf("repo required")
	}
	token := g.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return "", 0, fmt.Errorf("no GitHub token (set $GITHUB_TOKEN)")
	}
	base := g.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := g.HTTP
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	payload := map[string]any{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	url := fmt.Sprintf("%s/repos/%s/issues", base, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body2, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("github API %d: %s", resp.StatusCode, string(body2))
	}
	var out struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	if err := json.Unmarshal(body2, &out); err != nil {
		return "", 0, fmt.Errorf("decode response: %w", err)
	}
	return out.HTMLURL, out.Number, nil
}
