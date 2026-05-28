package detectors

import (
	"strings"
	"testing"
)

func TestLoadWatchlist(t *testing.T) {
	src := `
projects:
  - name: intel-amt-linux
    github: 88plug/intel-amt-linux
    aur: intel-amt-linux
    distinctive_strings:
      - "Native Linux GUI + CLI for Intel AMT"
      - "imrsdk-linux"
    license_path: LICENSE.md
  - name: k3d-gpu
    github: 88plug/k3d-gpu
    distinctive_strings:
      - k3d-gpu
`
	wl, err := LoadWatchlist(strings.NewReader(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(wl.Projects) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(wl.Projects))
	}
	p := wl.Projects[0]
	if p.Name != "intel-amt-linux" {
		t.Errorf("name: %q", p.Name)
	}
	if p.GitHub != "88plug/intel-amt-linux" {
		t.Errorf("github: %q", p.GitHub)
	}
	if p.AUR != "intel-amt-linux" {
		t.Errorf("aur: %q", p.AUR)
	}
	if len(p.DistinctiveStrings) != 2 {
		t.Fatalf("strings: %v", p.DistinctiveStrings)
	}
	if p.DistinctiveStrings[1] != "imrsdk-linux" {
		t.Errorf("strings[1]: %q", p.DistinctiveStrings[1])
	}
	if p.LicensePath != "LICENSE.md" {
		t.Errorf("license: %q", p.LicensePath)
	}
}

func TestLoadWatchlistComments(t *testing.T) {
	src := `
# top comment
projects:
  - name: foo  # inline
    distinctive_strings:
      - bar
`
	wl, err := LoadWatchlist(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(wl.Projects) != 1 || wl.Projects[0].Name != "foo" {
		t.Fatalf("got %#v", wl.Projects)
	}
}
