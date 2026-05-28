package gate

import (
	"strings"
	"testing"
	"time"
)

// The exact text below must appear verbatim in any rendered DMCA. These
// constants are duplicated literally (not referenced from gate.go) so that an
// accidental edit to PerjuryStatement / GoodFaithStatement is caught by this
// test — they are required by GitHub's filing guide.
const (
	wantPerjury = "I swear, under penalty of perjury, that the information in this notification is accurate and that I am the copyright owner, or am authorized to act on behalf of the owner, of an exclusive right that is allegedly infringed."
	wantGood    = "I have a good faith belief that use of the copyrighted materials described above on the infringing web pages is not authorized by the copyright owner, or its agent, or the law. I have taken fair use into consideration."
)

func TestPerjuryAndGoodFaith_Verbatim(t *testing.T) {
	if PerjuryStatement != wantPerjury {
		t.Fatalf("perjury statement drifted from GitHub's required text\nhave: %s\nwant: %s", PerjuryStatement, wantPerjury)
	}
	if GoodFaithStatement != wantGood {
		t.Fatalf("good-faith statement drifted from GitHub's required text\nhave: %s\nwant: %s", GoodFaithStatement, wantGood)
	}
}

func TestDMCATemplate_RendersAllRequiredFields(t *testing.T) {
	g, _ := New(Config{
		DraftsDir:        t.TempDir(),
		DispositionsPath: t.TempDir() + "/d.jsonl",
		Now:              func() time.Time { return time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC) },
	})
	v := mkVerdict(SeverityHigh)
	body, err := g.renderDMCA(v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	mustContain := []string{
		"DMCA TAKEDOWN NOTICE",
		"Date:",
		"GitHub's filing guide",
		"Copyrighted work allegedly infringed",
		v.OurURL,
		"Infringing material",
		v.ViolatorURL,
		"Remediation requested",
		"My contact information",
		"Alleged infringer",
		wantGood,
		wantPerjury,
		"Signed: ____________ (your name + date)",
		"Physical or electronic signature",
		"Evidence pack",
		"Rekor transparency-log",
		"OpenTimestamps",
		"RFC 3161",
		"24296fb24b8ad77a",
		"17 U.S.C. §512(c)(3)(A)(i)",
	}
	for _, frag := range mustContain {
		if !strings.Contains(body, frag) {
			t.Errorf("DMCA template missing required fragment: %q", frag)
		}
	}
}

func TestCeaseDesistTemplate_DoesNotImplyDMCA(t *testing.T) {
	g, _ := New(Config{
		DraftsDir:        t.TempDir(),
		DispositionsPath: t.TempDir() + "/d.jsonl",
		Now:              func() time.Time { return time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC) },
	})
	body, err := g.renderCeaseDesist(mkVerdict(SeverityMed))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(body, "DMCA TAKEDOWN NOTICE") {
		t.Fatalf("C&D template should not contain a DMCA header")
	}
	if strings.Contains(body, wantPerjury) {
		t.Fatalf("C&D template should NOT contain the perjury statement")
	}
	for _, frag := range []string{
		"cease-and-desist",
		"FSL-1.1-ALv2",
		"14 days",
	} {
		if !strings.Contains(strings.ToLower(body), strings.ToLower(frag)) {
			t.Errorf("C&D missing fragment: %q", frag)
		}
	}
}

func TestSignerFields_BlankByDefault(t *testing.T) {
	g, _ := New(Config{
		DraftsDir:        t.TempDir(),
		DispositionsPath: t.TempDir() + "/d.jsonl",
		Now:              func() time.Time { return time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC) },
	})
	body, err := g.renderDMCA(mkVerdict(SeverityHigh))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, marker := range []string{
		"_______________________________ (fill in)",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("default DMCA should leave signer fields blank; missing %q", marker)
		}
	}
}
