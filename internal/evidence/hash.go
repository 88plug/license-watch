package evidence

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile streams the file at path through SHA-256 and SHA-512 in one
// pass and returns both hex digests. No buffering in memory beyond
// io.Copy's 32 KiB chunk.
func HashFile(path string) (sha256hex, sha512hex string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h256 := sha256.New()
	h512 := sha512.New()
	mw := io.MultiWriter(h256, h512)

	n, err := io.Copy(mw, f)
	if err != nil {
		return "", "", 0, fmt.Errorf("hash %s: %w", path, err)
	}

	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil)), n, nil
}

// SHA256Bytes returns the lowercase hex SHA-256 of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewArtifact hashes the file at path and returns an Artifact record.
func NewArtifact(path, kind, source, note string) (Artifact, error) {
	s256, s512, n, err := HashFile(path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Path:   path,
		Kind:   kind,
		SHA256: s256,
		SHA512: s512,
		Bytes:  n,
		Source: source,
		Note:   note,
	}, nil
}
