package evidence

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Committer commits the evidence directory into the evidence repo
// (sibling repo or submodule) using `gitsign commit -S` so the commit
// itself is anchored in Rekor — and pushes to >=2 remotes. The
// adversary must compromise BOTH GitHub and Codeberg to alter history.
type Committer struct {
	// RepoDir is the working tree of the evidence repo.
	RepoDir string
	// GitsignBin defaults to "gitsign".
	GitsignBin string
	// GitBin defaults to "git".
	GitBin string
	// Remotes is the ordered list of remotes to push to.
	// Default: ["origin", "codeberg"].
	Remotes []string
	// Branch is the target branch. Default: "main".
	Branch string
}

// NewCommitter returns defaults.
func NewCommitter(repoDir string) *Committer {
	return &Committer{
		RepoDir:    repoDir,
		GitsignBin: "gitsign",
		GitBin:     "git",
		Remotes:    []string{"origin", "codeberg"},
		Branch:     "main",
	}
}

// CommitAndPush stages everything in evidenceSubdir (relative path
// inside RepoDir), creates a gitsign commit, and pushes to every
// remote. Returns the resulting commit SHA.
func (c *Committer) CommitAndPush(ctx context.Context, evidenceSubdir, message string) (sha string, err error) {
	if err := c.git(ctx, "add", evidenceSubdir); err != nil {
		return "", err
	}
	// gitsign is invoked as a git wrapper:
	//   git -c gpg.x509.program=gitsign -c gpg.format=x509 -c commit.gpgsign=true commit -S -m ...
	commitArgs := []string{
		"-c", "gpg.x509.program=" + c.GitsignBin,
		"-c", "gpg.format=x509",
		"-c", "commit.gpgsign=true",
		"commit", "-S", "-m", message,
	}
	if err := c.git(ctx, commitArgs...); err != nil {
		return "", fmt.Errorf("gitsign commit: %w", err)
	}
	out, err := c.gitOut(ctx, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	sha = strings.TrimSpace(out)

	var pushErrs []string
	for _, remote := range c.Remotes {
		if err := c.git(ctx, "push", remote, c.Branch); err != nil {
			pushErrs = append(pushErrs, fmt.Sprintf("%s: %v", remote, err))
		}
	}
	// Accept partial success — single-remote push still gives us evidence
	// continuity, but log every failure into the manifest by returning it.
	if len(pushErrs) == len(c.Remotes) {
		return sha, fmt.Errorf("all pushes failed: %s", strings.Join(pushErrs, "; "))
	}
	if len(pushErrs) > 0 {
		return sha, fmt.Errorf("partial push failure: %s", strings.Join(pushErrs, "; "))
	}
	return sha, nil
}

func (c *Committer) git(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, c.GitBin, args...)
	cmd.Dir = c.RepoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

func (c *Committer) gitOut(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.GitBin, args...)
	cmd.Dir = c.RepoDir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
