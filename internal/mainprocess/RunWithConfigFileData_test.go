package mainprocess_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/mainprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func newMockOpa(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRsaStandardRun(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "ca_id_1"

	opaUrl := newMockOpa(t).URL

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &opaUrl,
				OpaUrlRevoke:  &opaUrl,
				OpaUrlIssueCa: &opaUrl,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err != nil {
		t.Error(err)
		return
	}
}

func TestRsaInvalidDatadir(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := filepath.Join(t.TempDir(), "testinvaliddir")
	if err := os.WriteFile(dataDirectory, []byte{}, os.FileMode(0o644)); err != nil {
		t.Error(err)
		return
	}
	caId := "ca_id_1"

	opaUrl := newMockOpa(t).URL

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &opaUrl,
				OpaUrlRevoke:  &opaUrl,
				OpaUrlIssueCa: &opaUrl,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("erro expected")
		return
	} else {
		t.Log(err)
	}
}

func TestRsaLockedDataDirectoryFails(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()

	unlockDataDirectory, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockDataDirectory()

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs:  map[string]types.CertificateAuthorityType{},
	}
	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected ErrDataDirectoryLocked, got %v", err)
	}
}

func TestRsaInvalidCaId(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "ca.invalid"

	opaUrl := newMockOpa(t).URL

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject: types.CertificateAuthoritySubjectType{
					CommonName: "test_ca_1",
				},
				KeyConfig: types.KeyConfigType{
					Type: "rsa",
					Config: types.KeyTypeRsaConfigType{
						Size: 2048,
					},
				},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &opaUrl,
				OpaUrlRevoke:  &opaUrl,
				OpaUrlIssueCa: &opaUrl,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("erro expected")
		return
	} else {
		t.Log(err)
	}
}

func TestRsaMissingOpaUrlFails(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "ca_id_1"

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject:   types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
				KeyConfig: types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 2048}},
				CrlTtl:    12 * time.Hour,
				Validity:  testCaValidity,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("expected error when OPA URLs are missing")
	} else if !errors.Is(err, types.ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestRsaOpaDeniedFailsRun(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "ca_id_1"

	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": false}`))
	}))
	defer opaServer.Close()
	opaUrl := opaServer.URL

	csrDir := filepath.Join(dataDirectory, caId, "data", "csr")
	if err := os.MkdirAll(csrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "www.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.WriteFile(filepath.Join(csrDir, "test.csr.pem"), csrPem, 0o644); err != nil {
		t.Fatal(err)
	}

	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject:       types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
				KeyConfig:     types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 2048}},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &opaUrl,
				OpaUrlRevoke:  &opaUrl,
				OpaUrlIssueCa: &opaUrl,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err == nil {
		t.Error("expected run to fail when OPA denies")
	}

	crtDir := filepath.Join(dataDirectory, caId, "data", "crt")
	entries, err := os.ReadDir(crtDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "1.crt.pem" {
		t.Fatalf("denied request must not write a certificate, crt dir: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(csrDir, "test.csr.pem")); !os.IsNotExist(err) {
		t.Fatalf("denied request must leave the spool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(csrDir, "signature-failed", "test.csr.pem")); err != nil {
		t.Fatalf("denied request must move to the signature-failed directory: %v", err)
	}
}

func TestRsaCliOpaInputContract(t *testing.T) {
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "ca_id_1"

	type receivedOpaInput struct {
		Input struct {
			Runtime             string `json:"runtime"`
			Authorization       string `json:"authorization"`
			ProposedCertificate struct {
				IsCA bool `json:"is_ca"`
			} `json:"proposed_certificate"`
		} `json:"input"`
	}
	type receivedOpaCall struct {
		path  string
		input receivedOpaInput
		raw   string
	}
	received := []receivedOpaCall{}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("cannot read OPA body: %v", err)
		}
		var input receivedOpaInput
		if err := json.Unmarshal(raw, &input); err != nil {
			t.Errorf("cannot decode OPA input %q: %v", raw, err)
		}
		received = append(received, receivedOpaCall{path: r.URL.Path, input: input, raw: string(raw)})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": true}`))
	}))
	defer opaServer.Close()

	csrDir := filepath.Join(dataDirectory, caId, "data", "csr")
	if err := os.MkdirAll(csrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	leafCsrPem := newCliCsrPem(t, pkix.Name{CommonName: "www.example.com"}, nil)
	if err := os.WriteFile(filepath.Join(csrDir, "leaf.csr.pem"), leafCsrPem, 0o644); err != nil {
		t.Fatal(err)
	}
	caTrueCsrPem := newCliCsrPem(t, pkix.Name{CommonName: "sub-ca.example.com"}, caTruePkixExtensions())
	if err := os.WriteFile(filepath.Join(csrDir, "ca.csr.pem"), caTrueCsrPem, 0o644); err != nil {
		t.Fatal(err)
	}

	urlSign := opaServer.URL + "/sign"
	urlIssueCa := opaServer.URL + "/issue_ca"
	urlRevoke := opaServer.URL + "/revoke"
	configObject := types.ConfigFileType{
		DataDirectory: dataDirectory,
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			caId: {
				Subject:       types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
				KeyConfig:     types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 2048}},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &urlSign,
				OpaUrlRevoke:  &urlRevoke,
				OpaUrlIssueCa: &urlIssueCa,
			},
		},
	}

	if err := mainprocess.RunWithConfigFileData(context.Background(), logger, configObject); err != nil {
		t.Error(err)
		return
	}

	if len(received) != 4 {
		t.Fatalf("expected 4 OPA calls (pre+post per CSR), got %d", len(received))
	}
	countByPath := map[string]int{}
	byPath := map[string]receivedOpaCall{}
	for _, one := range received {
		countByPath[one.path]++
		byPath[one.path] = one
	}
	for _, path := range []string{"/sign", "/issue_ca"} {
		if countByPath[path] != 2 {
			t.Errorf("%s: want 2 OPA calls, got %d", path, countByPath[path])
		}
		one, ok := byPath[path]
		if !ok {
			t.Errorf("no OPA call to %s, received %v", path, received)
			continue
		}
		if one.input.Input.Runtime != "cli" {
			t.Errorf("%s: input.runtime = %q, want cli", path, one.input.Input.Runtime)
		}
		if one.input.Input.Authorization != "" {
			t.Errorf("%s: input.authorization = %q, want empty", path, one.input.Input.Authorization)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(one.raw), &body); err != nil {
			t.Fatal(err)
		}
		input, ok := body["input"].(map[string]any)
		if !ok {
			t.Errorf("%s: OPA body %q is not an {\"input\": ...} envelope", path, one.raw)
			continue
		}
		if _, hasRemoteAddr := input["remote_addr"]; hasRemoteAddr {
			t.Errorf("%s: CLI input must not carry remote_addr, got %q", path, one.raw)
		}
	}
	if byPath["/sign"].input.Input.ProposedCertificate.IsCA {
		t.Error("/sign must authorize a non-CA certificate")
	}
	if !byPath["/issue_ca"].input.Input.ProposedCertificate.IsCA {
		t.Error("/issue_ca must authorize a CA certificate")
	}
}

func newCliCsrPem(t *testing.T, subject pkix.Name, extraExtensions []pkix.Extension) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         subject,
		ExtraExtensions: extraExtensions,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func caTruePkixExtensions() []pkix.Extension {
	return []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
	}
}
