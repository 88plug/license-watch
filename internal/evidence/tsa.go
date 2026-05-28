package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// TSAClient submits SHA-256 digests to an RFC 3161 Time Stamping
// Authority and writes the binary TSR reply to disk.
//
// RFC 3161 §3.4 — request is a TimeStampReq DER, the response is a
// TimeStampResp DER. We construct the request manually so this code
// has zero external dependencies. The response is stored verbatim as
// .tsr — `openssl ts -verify -in foo.tsr -data foo -CAfile chain.pem`
// will authenticate it later.
type TSAClient struct {
	Name       string
	URL        string
	HTTPClient *http.Client
}

// NewFreeTSA returns a client preconfigured for FreeTSA.org.
func NewFreeTSA() *TSAClient {
	return &TSAClient{
		Name:       "FreeTSA",
		URL:        FreeTSAURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewDigicertTSA returns a client preconfigured for DigiCert.
func NewDigicertTSA() *TSAClient {
	return &TSAClient{
		Name:       "DigiCert",
		URL:        DigicertURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// tsaMessageImprint is the ASN.1 structure RFC 3161 §2.4.1.
type tsaMessageImprint struct {
	HashAlgorithm pkixAlgorithmIdentifier
	HashedMessage []byte
}

// pkixAlgorithmIdentifier mirrors crypto/x509/pkix.AlgorithmIdentifier
// (kept local so we have zero non-stdlib imports).
type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tsaRequest struct {
	Version        int
	MessageImprint tsaMessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []asn1.RawValue       `asn1:"tag:0,optional"`
}

// oidSHA256 = 2.16.840.1.101.3.4.2.1
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// BuildRequest builds a DER-encoded RFC 3161 request for the given digest.
func BuildRequest(sha256digest []byte, certReq bool) ([]byte, error) {
	if len(sha256digest) != sha256.Size {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(sha256digest))
	}
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, err
	}
	req := tsaRequest{
		Version: 1,
		MessageImprint: tsaMessageImprint{
			HashAlgorithm: pkixAlgorithmIdentifier{
				Algorithm: oidSHA256,
				// NULL parameters per RFC 3370 §2.1
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			HashedMessage: sha256digest,
		},
		Nonce:   nonce,
		CertReq: certReq,
	}
	return asn1.Marshal(req)
}

// Stamp submits the given filePath, writes the TSR alongside it
// (filePath + ".tsr"), and returns a Timestamp record.
func (c *TSAClient) Stamp(ctx context.Context, filePath string) (Timestamp, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Timestamp{}, fmt.Errorf("read %s: %w", filePath, err)
	}
	sum := sha256.Sum256(data)
	digestHex := fmt.Sprintf("%x", sum)

	reqDER, err := BuildRequest(sum[:], true)
	if err != nil {
		return Timestamp{}, fmt.Errorf("build tsr: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return Timestamp{}, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")
	httpReq.Header.Set("User-Agent", "license-watch/L6")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return Timestamp{}, fmt.Errorf("tsa post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Timestamp{}, fmt.Errorf("tsa %s status %d: %s", c.Name, resp.StatusCode, string(body))
	}
	tsrBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Timestamp{}, err
	}

	tsrPath := filepath.Join(filepath.Dir(filePath), filepath.Base(filePath)+"."+sanitizeName(c.Name)+".tsr")
	if err := os.WriteFile(tsrPath, tsrBody, 0o644); err != nil {
		return Timestamp{}, err
	}

	return Timestamp{
		TSA:       c.Name,
		URL:       c.URL,
		Digest:    digestHex,
		TSRPath:   tsrPath,
		TSRSHA256: SHA256Bytes(tsrBody),
		IssuedAt:  time.Now().UTC(),
	}, nil
}

func sanitizeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
