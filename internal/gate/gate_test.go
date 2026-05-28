package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeOpener struct {
	gotRepo   string
	gotTitle  string
	gotBody   string
	gotLabels []string
	url       string
	num       int
	err       error
}

func (f *fakeOpener) OpenIssue(_ context.Context, repo, title, body string, labels []string) (string, int, error) {
	f.gotRepo, f.gotTitle, f.gotBody, f.gotLabels = repo, title, body, labels
	return f.url, f.num, f.err
}

func newGate(t *testing.T, opener IssueOpener) (*Gate, string) {
	t.Helper()
	dir := t.TempDir()
	g, err := New(Config{
		Repo:             "88plug/license-watch",
		DispositionsPath: filepath.Join(dir, "dispositions.jsonl"),
		DraftsDir:        filepath.Join(dir, "drafts"),
		IssueOpener:      opener,
		Now:              func() time.Time { return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, dir
}

func mkVerdict(sev string) *Verdict {
	return &Verdict{
		CandidateID:         "cand-001",
		Severity:            sev,
		CloneType:           "Type-2",
		ViolatorURL:         "https://github.com/bad/clone",
		OurURL:              "https://github.com/88plug/license-watch",
		OurAuthorshipProof:  "First commit 2026-01-01 by Andrew Mello.",
		InfringedClauses:    []string{"func ScanRepo() copied verbatim", "README first paragraph copied"},
		EvidenceManifestURL: "https://r2.example/evidence/cand-001/manifest.json",
		PageVaultURL:        "https://r2.example/evidence/cand-001/vault.html",
		WACZURL:             "https://r2.example/evidence/cand-001/capture.wacz",
		WaybackURL:          "https://web.archive.org/web/20260527/https://github.com/bad/clone",
		RekorEntries:        []string{"24296fb24b8ad77a"},
		OTSProofs:           []string{"https://r2.example/evidence/cand-001/capture.ots"},
		TSAProofs:           []string{"https://r2.example/evidence/cand-001/freetsa.tsr"},
	}
}

func TestDecide_Low_LogsOnly(t *testing.T) {
	op := &fakeOpener{url: "https://github.com/88plug/license-watch/issues/1", num: 1}
	g, dir := newGate(t, op)
	d, err := g.Decide(context.Background(), mkVerdict(SeverityLow))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Action != "log_only" {
		t.Fatalf("low → expected log_only, got %s", d.Action)
	}
	if op.gotTitle != "" {
		t.Fatalf("low should not open an issue, got title=%q", op.gotTitle)
	}
	// dispositions.jsonl should have exactly one line.
	rows, err := ReadDispositions(filepath.Join(dir, "dispositions.jsonl"))
	if err != nil {
		t.Fatalf("ReadDispositions: %v", err)
	}
	if len(rows) != 1 || rows[0].Action != "log_only" {
		t.Fatalf("expected 1 log_only row, got %+v", rows)
	}
}

func TestDecide_Med_OpensCeaseDesistIssue(t *testing.T) {
	op := &fakeOpener{url: "https://github.com/88plug/license-watch/issues/2", num: 2}
	g, _ := newGate(t, op)
	d, err := g.Decide(context.Background(), mkVerdict(SeverityMed))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Action != "issue_med" {
		t.Fatalf("med → expected issue_med, got %s", d.Action)
	}
	if !contains(op.gotLabels, "severity:med") {
		t.Fatalf("expected severity:med label, got %v", op.gotLabels)
	}
	if !strings.Contains(op.gotTitle, "[severity:med]") {
		t.Fatalf("title missing severity tag: %s", op.gotTitle)
	}
	// Body should be a cease-and-desist, NOT a DMCA.
	if strings.Contains(op.gotBody, "DMCA TAKEDOWN NOTICE") {
		t.Fatalf("med should be cease-and-desist, not DMCA")
	}
	if !strings.Contains(op.gotBody, "Cease-and-desist") {
		t.Fatalf("med body missing C&D header")
	}
	if !strings.Contains(op.gotBody, "https://github.com/bad/clone") {
		t.Fatalf("med body missing violator URL")
	}
}

func TestDecide_High_OpensDMCAIssue(t *testing.T) {
	op := &fakeOpener{url: "https://github.com/88plug/license-watch/issues/3", num: 3}
	g, _ := newGate(t, op)
	d, err := g.Decide(context.Background(), mkVerdict(SeverityHigh))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Action != "issue_high" {
		t.Fatalf("high → expected issue_high, got %s", d.Action)
	}
	wantLabels := []string{"severity:high", "state:open", "human-review", "dmca-draft"}
	for _, l := range wantLabels {
		if !contains(op.gotLabels, l) {
			t.Fatalf("missing label %s in %v", l, op.gotLabels)
		}
	}
	if !strings.Contains(op.gotBody, "DMCA TAKEDOWN NOTICE") {
		t.Fatalf("high body missing DMCA header")
	}
	if !strings.Contains(op.gotBody, PerjuryStatement) {
		t.Fatalf("high body missing perjury statement verbatim")
	}
	if !strings.Contains(op.gotBody, GoodFaithStatement) {
		t.Fatalf("high body missing good-faith statement verbatim")
	}
	if !strings.Contains(op.gotBody, "24296fb24b8ad77a") {
		t.Fatalf("high body missing rekor entry")
	}
	if !strings.Contains(op.gotBody, "Signed: ____________") {
		t.Fatalf("high body missing signature line placeholder")
	}
	// Confirm signer fields are blank placeholders (we didn't configure a signer).
	if !strings.Contains(op.gotBody, "_______________________________ (fill in)") {
		t.Fatalf("signer fields should be blank fill-in placeholders by default")
	}
}

func TestDecide_Unknown_Errors(t *testing.T) {
	g, dir := newGate(t, &fakeOpener{})
	_, err := g.Decide(context.Background(), mkVerdict("critical"))
	if err == nil {
		t.Fatalf("expected error for unknown severity")
	}
	// disposition still appended with error captured.
	rows, _ := ReadDispositions(filepath.Join(dir, "dispositions.jsonl"))
	if len(rows) != 1 || rows[0].Error == "" {
		t.Fatalf("expected one row with Error, got %+v", rows)
	}
}

func TestDispositions_AppendOnly_JSONL(t *testing.T) {
	op := &fakeOpener{url: "https://github.com/x/y/issues/9", num: 9}
	g, dir := newGate(t, op)
	for _, sev := range []string{SeverityLow, SeverityMed, SeverityHigh} {
		v := mkVerdict(sev)
		v.CandidateID = "cand-" + sev
		if _, err := g.Decide(context.Background(), v); err != nil {
			t.Fatalf("Decide(%s): %v", sev, err)
		}
	}
	// Each line must be valid JSON; file must have exactly 3 lines.
	raw, err := os.ReadFile(filepath.Join(dir, "dispositions.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, l := range lines {
		var d Disposition
		if err := json.Unmarshal([]byte(l), &d); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestDecide_HighWithSigner_RendersSignerName(t *testing.T) {
	op := &fakeOpener{}
	dir := t.TempDir()
	g, err := New(Config{
		Repo:             "88plug/license-watch",
		DispositionsPath: filepath.Join(dir, "dispositions.jsonl"),
		DraftsDir:        filepath.Join(dir, "drafts"),
		IssueOpener:      op,
		SignerName:       "Andrew Mello",
		SignerAddress:    "PO Box 1, Earth",
		SignerEmail:      "andrew@88plug.com",
		Now:              func() time.Time { return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := g.Decide(context.Background(), mkVerdict(SeverityHigh)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(op.gotBody, "Andrew Mello") {
		t.Fatalf("body should include signer name when configured")
	}
	if !strings.Contains(op.gotBody, "PO Box 1, Earth") {
		t.Fatalf("body should include signer address when configured")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
