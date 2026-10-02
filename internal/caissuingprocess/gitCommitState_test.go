package caissuingprocess

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os/user"
	"strings"
	"testing"
	"time"
)

func TestGitAuthorSignatureFallsBackWhenUserUnresolvable(t *testing.T) {
	originalLookup := gitCurrentUser
	gitCurrentUser = func() (*user.User, error) {
		return nil, errors.New("user: unknown userid 12345")
	}
	defer func() { gitCurrentUser = originalLookup }()

	author := gitAuthorSignature("container-host")
	if author.Name != "" {
		t.Errorf("expected an empty author name, got %q", author.Name)
	}
	if author.Email != "container-host" {
		t.Errorf("expected the hostname as author email, got %q", author.Email)
	}
}

func TestGitAuthorSignatureUsesCurrentUser(t *testing.T) {
	originalLookup := gitCurrentUser
	gitCurrentUser = func() (*user.User, error) {
		return &user.User{Username: "testuser", Name: "Test User"}, nil
	}
	defer func() { gitCurrentUser = originalLookup }()

	author := gitAuthorSignature("container-host")
	if author.Name != "Test User" {
		t.Errorf("expected the user name as author name, got %q", author.Name)
	}
	if author.Email != "testuser@container-host" {
		t.Errorf("expected user@host as author email, got %q", author.Email)
	}
}

// forgeLines are the lines an injected newline in a subject field would have
// been able to put into a plain-text commit message.
var forgeLines = []string{
	"sha256: 0000000000000000000000000000000000000000000000000000000000000000",
	"subject: forged",
}

func TestGitIssueCommitMessageEscapesCsrContributedValues(t *testing.T) {
	injectedOU := "audit\n" + forgeLines[0] + "\n" + forgeLines[1]
	certificate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "www.example.com",
			OrganizationalUnit: []string{injectedOU},
		},
		SerialNumber: big.NewInt(42),
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC),
		Raw:          []byte("certificate raw bytes"),
	}

	message := gitIssueCommitMessage(certificate)
	t.Logf("commit message:\n%s", message)

	// The forged lines must not be able to start a line of their own in the
	// history: the newlines live inside the JSON string, escaped.
	for _, line := range strings.Split(message, "\n") {
		for _, forged := range forgeLines {
			if strings.HasPrefix(line, forged) {
				t.Errorf("forged line %q starts a line of the commit message", forged)
			}
		}
	}

	// The record still round-trips as JSON, with the CSR-contributed values
	// intact and the certificate's own fingerprint in the sha256 field.
	record := struct {
		Subject   string   `json:"subject"`
		Serial    string   `json:"serial"`
		DNSNames  []string `json:"dns_names"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		SHA256    string   `json:"sha256"`
	}{}
	recordJSON := message[strings.Index(message, "{\n"):]
	if err := json.Unmarshal([]byte(recordJSON), &record); err != nil {
		t.Fatalf("commit record does not parse as JSON: %v", err)
	}
	digest := sha256.Sum256(certificate.Raw)
	wantFingerprint := hex.EncodeToString(digest[:])
	if record.Subject != "CN=www.example.com,OU="+injectedOU {
		t.Errorf("subject did not survive the JSON round-trip, got %q", record.Subject)
	}
	if record.Serial != "42" {
		t.Errorf("serial did not survive the JSON round-trip, got %q", record.Serial)
	}
	if len(record.DNSNames) != 1 || record.DNSNames[0] != "www.example.com" {
		t.Errorf("dns_names did not survive the JSON round-trip, got %v", record.DNSNames)
	}
	if record.SHA256 != wantFingerprint {
		t.Errorf("sha256 field is %q, want %q", record.SHA256, wantFingerprint)
	}
}

func TestGitIssueCommitMessageOmitsEmptyDNSNames(t *testing.T) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Raw:          []byte("x"),
	}
	message := gitIssueCommitMessage(certificate)
	recordJSON := message[strings.Index(message, "{\n"):]
	if strings.Contains(recordJSON, "dns_names") {
		t.Errorf("empty dns_names should be omitted from the record, got %s", recordJSON)
	}
	if !strings.Contains(recordJSON, `"serial": "1"`) {
		t.Errorf("serial is missing from the record, got %s", recordJSON)
	}
}
