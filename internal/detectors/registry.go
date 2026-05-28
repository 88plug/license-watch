package detectors

// All returns every detector in canonical order. Append-only.
func All() []Detector {
	return []Detector{
		NewGHArchive(),
		NewNPM(),
		NewPyPI(),
		NewAUR(),
		NewCrates(),
		NewDockerHub(),
		NewEcosystems(),
		NewGitHubCode(),
		NewReddit(),
		NewHN(),
		NewLobsters(),
		NewMastodon(),
		NewBluesky(),
		NewDevTo(),
		NewStackExchange(),
		NewYouTube(),
		NewHF(),
		NewArtifactHub(),
		NewGitLab(),
		NewCodeberg(),
		NewTelegram(),
	}
}
