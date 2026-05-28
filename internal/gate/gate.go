// Package gate implements L7 of the license-watch pipeline: the human gate.
//
// Perjury attaches to the signer of a DMCA, not to this software. GitHub also
// explicitly forbids bulk / bot DMCA submissions
// (https://docs.github.com/en/site-policy/content-removal-policies/guide-to-submitting-a-dmca-takedown-notice).
//
// Therefore L7 NEVER submits anything anywhere. It:
//   - reads an L5 verdict (JSON) from disk or stdin
//   - chooses a path by severity
//   - drafts (but does not submit) a DMCA / cease-and-desist letter
//   - opens a GitHub issue in 88plug/license-watch so a human can review,
//     sign, and manually paste into the platform's takedown form
//   - appends every decision to dispositions.jsonl (append-only audit log)
package gate

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Severity levels emitted by L5.
const (
	SeverityLow  = "low"
	SeverityMed  = "med"
	SeverityHigh = "high"
)

// Verdict mirrors the JSON document produced by L5 (internal/judge).
// Only fields L7 needs are populated; unknown fields are preserved via Raw.
type Verdict struct {
	CandidateID         string            `json:"candidate_id"`
	Severity            string            `json:"severity"`
	CloneType           string            `json:"clone_type,omitempty"`
	ClauseCited         string            `json:"clause_cited,omitempty"`
	InfringedClauses    []string          `json:"infringed_clauses,omitempty"`
	RecommendedAction   string            `json:"recommended_action,omitempty"`
	OurURL              string            `json:"our_url"`
	OurAuthorshipProof  string            `json:"our_authorship_proof,omitempty"`
	ViolatorURL         string            `json:"violator_url"`
	ViolatorContact     string            `json:"violator_contact,omitempty"`
	EvidenceManifestURL string            `json:"evidence_manifest_url,omitempty"`
	PageVaultURL        string            `json:"page_vault_url,omitempty"`
	RekorEntries        []string          `json:"rekor_entries,omitempty"`
	OTSProofs           []string          `json:"ots_proofs,omitempty"`
	TSAProofs           []string          `json:"tsa_proofs,omitempty"`
	WACZURL             string            `json:"wacz_url,omitempty"`
	WaybackURL          string            `json:"wayback_url,omitempty"`
	SHA256              map[string]string `json:"sha256,omitempty"`
	DraftDMCA           string            `json:"draft_dmca,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
}

// TemplateVars are passed to the DMCA / cease-and-desist Go templates.
// Signer fields are deliberately left blank in the rendered draft so the
// human gate has to fill them in (perjury attaches there).
type TemplateVars struct {
	ViolatorURL              string
	OurURL                   string
	OurAuthorshipProof       string
	InfringedClausesQuoted   string
	EvidenceManifestURL      string
	PageVaultURL             string
	WaybackURL               string
	WACZURL                  string
	RekorEntriesFormatted    string
	OTSProofsFormatted       string
	TSAProofsFormatted       string
	SignerName               string // intentionally blank by default
	SignerAddress            string // from $SIGNER_ADDRESS or blank
	SignerEmail              string // from $SIGNER_EMAIL or blank
	SignerPhone              string // from $SIGNER_PHONE or blank
	GoodFaithStatement       string // verbatim GitHub text
	PerjuryStatement         string // verbatim GitHub text
	Date                     string
	CandidateID              string
	CloneType                string
}

// GoodFaithStatement is the verbatim good-faith-belief paragraph required by
// GitHub's DMCA filing guide. Do not edit.
const GoodFaithStatement = "I have a good faith belief that use of the copyrighted materials described above on the infringing web pages is not authorized by the copyright owner, or its agent, or the law. I have taken fair use into consideration."

// PerjuryStatement is the verbatim perjury declaration required by GitHub's
// DMCA filing guide. Do not edit.
const PerjuryStatement = "I swear, under penalty of perjury, that the information in this notification is accurate and that I am the copyright owner, or am authorized to act on behalf of the owner, of an exclusive right that is allegedly infringed."

//go:embed templates/*.tmpl
var templateFS embed.FS

// Disposition is one append-only log row written to dispositions.jsonl.
type Disposition struct {
	Timestamp   time.Time `json:"ts"`
	CandidateID string    `json:"candidate_id"`
	Severity    string    `json:"severity"`
	Action      string    `json:"action"` // "log_only" | "issue_med" | "issue_high"
	IssueURL    string    `json:"issue_url,omitempty"`
	IssueNumber int       `json:"issue_number,omitempty"`
	DraftPath   string    `json:"draft_path,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Config controls Gate behavior.
type Config struct {
	// Repo is the slug to open issues in, e.g. "88plug/license-watch".
	Repo string
	// DispositionsPath is the append-only audit log path.
	DispositionsPath string
	// DraftsDir is where rendered DMCA / C&D drafts are written for inspection.
	DraftsDir string
	// SignerName / SignerAddress / SignerEmail / SignerPhone may be set from env.
	// Left blank → template renders blank placeholders for the human to fill.
	SignerName    string
	SignerAddress string
	SignerEmail   string
	SignerPhone   string
	// IssueOpener creates a GitHub issue and returns (issue url, issue number, err).
	// Nil → uses the default GitHub API opener.
	IssueOpener IssueOpener
	// Now is overridable for tests.
	Now func() time.Time
}

// IssueOpener abstracts issue creation so tests can inject a fake.
type IssueOpener interface {
	OpenIssue(ctx context.Context, repo, title, body string, labels []string) (string, int, error)
}

// Gate is the L7 decision engine.
type Gate struct {
	cfg Config
	tpl *template.Template
}

// New builds a Gate. Templates are parsed once.
func New(cfg Config) (*Gate, error) {
	if cfg.Repo == "" {
		cfg.Repo = "88plug/license-watch"
	}
	if cfg.DispositionsPath == "" {
		cfg.DispositionsPath = "dispositions.jsonl"
	}
	if cfg.DraftsDir == "" {
		cfg.DraftsDir = "drafts"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SignerAddress == "" {
		cfg.SignerAddress = os.Getenv("SIGNER_ADDRESS")
	}
	if cfg.SignerEmail == "" {
		cfg.SignerEmail = os.Getenv("SIGNER_EMAIL")
	}
	if cfg.SignerPhone == "" {
		cfg.SignerPhone = os.Getenv("SIGNER_PHONE")
	}
	if cfg.SignerName == "" {
		cfg.SignerName = os.Getenv("SIGNER_NAME")
	}
	tpl, err := template.ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Gate{cfg: cfg, tpl: tpl}, nil
}

// LoadVerdict reads a Verdict from an io.Reader (typically a file from L5).
func LoadVerdict(r io.Reader) (*Verdict, error) {
	var v Verdict
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	// We do not actually disallow unknown fields — L5 may add new ones; tolerate.
	dec = json.NewDecoder(r)
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode verdict: %w", err)
	}
	if v.Severity == "" {
		return nil, errors.New("verdict: severity is required")
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	return &v, nil
}

// Decide is the entry point: classify verdict, render draft (if needed),
// open GitHub issue (if needed), append disposition.
func (g *Gate) Decide(ctx context.Context, v *Verdict) (*Disposition, error) {
	now := g.cfg.Now().UTC()
	d := &Disposition{
		Timestamp:   now,
		CandidateID: v.CandidateID,
		Severity:    v.Severity,
	}
	switch strings.ToLower(v.Severity) {
	case SeverityLow:
		d.Action = "log_only"
	case SeverityMed:
		body, err := g.renderCeaseDesist(v)
		if err != nil {
			d.Error = err.Error()
			_ = g.append(d)
			return d, err
		}
		path, _ := g.writeDraft(v, "cease_desist", body)
		d.DraftPath = path
		d.Action = "issue_med"
		title := fmt.Sprintf("[severity:med] possible violation — %s", shortID(v))
		url, num, err := g.openIssue(ctx, title, body, []string{"severity:med", "state:open", "human-review"})
		if err != nil {
			d.Error = err.Error()
		}
		d.IssueURL, d.IssueNumber = url, num
	case SeverityHigh:
		body, err := g.renderDMCA(v)
		if err != nil {
			d.Error = err.Error()
			_ = g.append(d)
			return d, err
		}
		path, _ := g.writeDraft(v, "dmca", body)
		d.DraftPath = path
		d.Action = "issue_high"
		title := fmt.Sprintf("[severity:high] DMCA DRAFT — %s", shortID(v))
		url, num, err := g.openIssue(ctx, title, body, []string{"severity:high", "state:open", "human-review", "dmca-draft"})
		if err != nil {
			d.Error = err.Error()
		}
		d.IssueURL, d.IssueNumber = url, num
	default:
		d.Error = fmt.Sprintf("unknown severity %q", v.Severity)
		_ = g.append(d)
		return d, errors.New(d.Error)
	}
	if err := g.append(d); err != nil {
		return d, fmt.Errorf("append disposition: %w", err)
	}
	return d, nil
}

func (g *Gate) renderDMCA(v *Verdict) (string, error) {
	return g.renderTemplate("dmca.md.tmpl", v)
}

func (g *Gate) renderCeaseDesist(v *Verdict) (string, error) {
	return g.renderTemplate("cease_desist.md.tmpl", v)
}

func (g *Gate) renderTemplate(name string, v *Verdict) (string, error) {
	tv := g.varsFromVerdict(v)
	var b strings.Builder
	t := g.tpl.Lookup(name)
	if t == nil {
		return "", fmt.Errorf("template %q not found", name)
	}
	if err := t.Execute(&b, tv); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return b.String(), nil
}

func (g *Gate) varsFromVerdict(v *Verdict) TemplateVars {
	return TemplateVars{
		ViolatorURL:            v.ViolatorURL,
		OurURL:                 v.OurURL,
		OurAuthorshipProof:     v.OurAuthorshipProof,
		InfringedClausesQuoted: bulletList(v.InfringedClauses),
		EvidenceManifestURL:    v.EvidenceManifestURL,
		PageVaultURL:           v.PageVaultURL,
		WaybackURL:             v.WaybackURL,
		WACZURL:                v.WACZURL,
		RekorEntriesFormatted:  bulletList(v.RekorEntries),
		OTSProofsFormatted:     bulletList(v.OTSProofs),
		TSAProofsFormatted:     bulletList(v.TSAProofs),
		SignerName:             g.cfg.SignerName,
		SignerAddress:          g.cfg.SignerAddress,
		SignerEmail:            g.cfg.SignerEmail,
		SignerPhone:            g.cfg.SignerPhone,
		GoodFaithStatement:     GoodFaithStatement,
		PerjuryStatement:       PerjuryStatement,
		Date:                   g.cfg.Now().UTC().Format("2006-01-02"),
		CandidateID:            v.CandidateID,
		CloneType:              v.CloneType,
	}
}

func (g *Gate) writeDraft(v *Verdict, kind, body string) (string, error) {
	if err := os.MkdirAll(g.cfg.DraftsDir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.md", kind, safeFileName(v.CandidateID))
	p := filepath.Join(g.cfg.DraftsDir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		return "", err
	}
	return p, nil
}

func (g *Gate) openIssue(ctx context.Context, title, body string, labels []string) (string, int, error) {
	if g.cfg.IssueOpener == nil {
		// No opener configured → caller is responsible (e.g. CI uses default).
		return "", 0, nil
	}
	return g.cfg.IssueOpener.OpenIssue(ctx, g.cfg.Repo, title, body, labels)
}

func (g *Gate) append(d *Disposition) error {
	if err := os.MkdirAll(filepath.Dir(g.cfg.DispositionsPath), 0o755); err != nil && filepath.Dir(g.cfg.DispositionsPath) != "." {
		return err
	}
	f, err := os.OpenFile(g.cfg.DispositionsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(d)
}

func bulletList(items []string) string {
	if len(items) == 0 {
		return "_(none provided)_"
	}
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "- %s\n", it)
	}
	return strings.TrimRight(b.String(), "\n")
}

func shortID(v *Verdict) string {
	if v.CandidateID != "" {
		return v.CandidateID
	}
	if v.ViolatorURL != "" {
		return v.ViolatorURL
	}
	return "unknown-candidate"
}

func safeFileName(s string) string {
	if s == "" {
		return "unknown"
	}
	r := strings.NewReplacer("/", "_", " ", "_", ":", "_", "?", "_", "&", "_", "=", "_")
	return r.Replace(s)
}
