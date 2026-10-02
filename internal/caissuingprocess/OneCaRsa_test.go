package caissuingprocess_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/opa"
	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
	"gopkg.in/yaml.v3"
)

func TestRsaOneCaBootstrap(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}

	{
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Error(err)
			return
		}
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "name 1",
			},
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
		if err != nil {
			t.Error(err)
			return
		}

		csrAsPem := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csr,
		})

		csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "example-csr-file.csr.pem")

		if err := os.WriteFile(csrFilename, csrAsPem, os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}
	}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}
}

func TestRsaInvalidCaIdOnlyDot(t *testing.T) {
	logger := &types.StdLogger{}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		".",
		t.TempDir(),
		types.CertificateAuthorityType{},
	); err != nil {
		if !errors.Is(err, types.ErrInvalidCaId) {
			t.Error(err)
		}
	} else {
		t.Error("expected error")
	}
}
func TestRsaInvalidCaIdWithSlash(t *testing.T) {
	logger := &types.StdLogger{}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		"/ok",
		t.TempDir(),
		types.CertificateAuthorityType{},
	); err != nil {
		if !errors.Is(err, types.ErrInvalidCaId) {
			t.Error(err)
		}
	} else {
		t.Error("expected error")
	}
}

func TestRsaInvalidPermittedIPRanges(t *testing.T) {
	logger := &types.StdLogger{}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		"test_ca_1",
		t.TempDir(),
		types.CertificateAuthorityType{
			Subject: types.CertificateAuthoritySubjectType{
				CommonName: "test_ca_1",
			},
			KeyConfig: types.KeyConfigType{
				Type: "rsa",
				Config: types.KeyTypeRsaConfigType{
					Size: 2048,
				},
			},
			CrlTtl:            12 * time.Hour,
			Validity:          testCaValidity,
			PermittedIPRanges: []string{"INVALIDME"},
			ExcludedIPRanges:  []string{"0.0.0.0/0"},
		},
	); err != nil {
	} else {
		t.Error("Expected error")
	}
}

func TestRsaInvalidExcludedIPRanges(t *testing.T) {
	logger := &types.StdLogger{}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		"test_ca_1",
		t.TempDir(),
		types.CertificateAuthorityType{
			Subject: types.CertificateAuthoritySubjectType{
				CommonName: "test_ca_1",
			},
			KeyConfig: types.KeyConfigType{
				Type: "rsa",
				Config: types.KeyTypeRsaConfigType{
					Size: 2048,
				},
			},
			CrlTtl:            12 * time.Hour,
			Validity:          testCaValidity,
			PermittedIPRanges: []string{"0.0.0.0/0"},
			ExcludedIPRanges:  []string{"INVALIDME"},
		},
	); err != nil {
	} else {
		t.Error("Expected error")
	}
}

func TestRsaSupportsEcdsaCsr(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},

		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}

	{
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "name 1",
			},
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
		if err != nil {
			t.Error(err)
			return
		}

		csrAsPem := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csr,
		})

		csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "example-csr-file.csr.pem")

		if err := os.WriteFile(csrFilename, csrAsPem, os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
	}

	if err := ca.IssueAllCsrInQueue(context.Background(), func(ctx context.Context, proposedCertificate *x509.Certificate) error { return nil }); err != nil {
		t.Error(err)
	}
}

func TestRsaIssueAllCsrInQueueQuarantinesPermanentFailures(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}

	spoolDir := filepath.Join(dataDirectory, caId, "data", "csr")
	writeCsr := func(name, commonName string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: commonName},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(spoolDir, name),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
	}

	// A spool holding one signable CSR, one denied by the policy, one with a
	// tampered signature, a stray text file and a stray directory.
	writeCsr("valid.csr.pem", "valid.example.com")
	writeCsr("denied.csr.pem", "denied.example.com")
	if err := os.WriteFile(filepath.Join(spoolDir, "tampered.csr.pem"),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\ntampered\n-----END CERTIFICATE REQUEST-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "notes.txt"),
		[]byte("reminder: renew the wildcard in autumn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(spoolDir, "old"), 0o755); err != nil {
		t.Fatal(err)
	}

	authorize := func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		if proposedCertificate.Subject.CommonName == "denied.example.com" {
			return opa.ErrNotAuthorized
		}
		return nil
	}

	err = ca.IssueAllCsrInQueue(context.Background(), authorize)
	if err == nil {
		t.Fatal("expected the first run to report the failed entries")
	}
	for _, name := range []string{"denied.csr.pem", "tampered.csr.pem"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the reported error must name %s, got: %v", name, err)
		}
	}

	assertPresent := func(dir, name string, mustBePresent bool) {
		t.Helper()
		_, err := os.Stat(filepath.Join(dir, name))
		if mustBePresent && err != nil {
			t.Errorf("%s must exist, got: %v", filepath.Join(dir, name), err)
		}
		if !mustBePresent && !os.IsNotExist(err) {
			t.Errorf("%s must not exist, got: %v", filepath.Join(dir, name), err)
		}
	}

	assertPresent(spoolDir, "valid.csr.pem", false) // signed and consumed
	assertPresent(spoolDir, "denied.csr.pem", false)
	assertPresent(spoolDir, "tampered.csr.pem", false)
	assertPresent(spoolDir, "notes.txt", true)
	assertPresent(spoolDir, "old", true)

	failedDir := filepath.Join(spoolDir, "signature-failed")
	assertPresent(failedDir, "denied.csr.pem", true)
	assertPresent(failedDir, "tampered.csr.pem", true)

	// What is left in the spool must not fail a second run.
	if err := ca.IssueAllCsrInQueue(context.Background(), authorize); err != nil {
		t.Errorf("expected the second run to succeed, got: %v", err)
	}
}

func TestRsaChangedKeySize(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}

	configData.KeyConfig = types.KeyConfigType{
		Type: "rsa",
		Config: types.KeyTypeRsaConfigType{
			Size: 1024,
		},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		if !errors.Is(err, types.ErrUnsupportedChangeToKeySize) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
	}
}

func TestRsaChangedSubjectFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}

	configData.Subject = types.CertificateAuthoritySubjectType{
		CommonName: "different_ca",
	}
	_, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if !errors.Is(err, caissuingprocess.ErrCaCertificateMismatch) {
		t.Errorf("expected ErrCaCertificateMismatch, got %v", err)
	}
	if err != nil {
		if !strings.Contains(err.Error(), "subject") {
			t.Errorf("expected the error to name the subject, got %v", err)
		}
	}
}

func TestRsaChangedValidityFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}

	// A different declared expiry is a different CA lifetime, and the report
	// names both instants, because the fix for it is to put back the date the
	// certificate actually carries.
	changedValidity := testCaValidity
	changedValidity.NotAfter = changedValidity.NotAfter.AddDate(3, 0, 0)
	configData.Validity = changedValidity
	_, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if !errors.Is(err, caissuingprocess.ErrCaCertificateMismatch) {
		t.Fatalf("expected ErrCaCertificateMismatch, got %v", err)
	}
	for _, expected := range []string{
		"2099-01-01T00:00:00Z",
		"2102-01-01T00:00:00Z",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("expected the report to name %s, got %v", expected, err)
		}
	}
}

func TestRsaSignCsrFilePastNotAfter(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "name 1"},
	}, privKey)
	if err != nil {
		t.Error(err)
		return
	}
	csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "past-notafter.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr,
	}), os.FileMode(0o644)); err != nil {
		t.Error(err)
		return
	}

	past := time.Now().UTC().Add(-time.Hour)
	_, err = ca.SignCsrFile(context.Background(), csrFilename, &past, func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		return nil
	})
	if !errors.Is(err, caissuingprocess.ErrInvalidLifetime) {
		t.Errorf("expected ErrInvalidLifetime, got %v", err)
	}
}

func TestRsaSignAuthorizeNotSerialized(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}

	csrFilenames := []string{}
	for i := 0; i < 2; i++ {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Error(err)
			return
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: fmt.Sprintf("name %d", i)},
		}, privKey)
		if err != nil {
			t.Error(err)
			return
		}
		csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", fmt.Sprintf("concurrent-%d.csr.pem", i))
		if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csr,
		}), os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}
		csrFilenames = append(csrFilenames, csrFilename)
	}

	var mu sync.Mutex
	var activeAuthorize int
	var maxActiveAuthorize int
	const authorizeLatency = 300 * time.Millisecond
	authorize := func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		mu.Lock()
		activeAuthorize++
		if activeAuthorize > maxActiveAuthorize {
			maxActiveAuthorize = activeAuthorize
		}
		mu.Unlock()
		time.Sleep(authorizeLatency)
		mu.Lock()
		activeAuthorize--
		mu.Unlock()
		return nil
	}

	signErrors := make(chan error, len(csrFilenames))
	var waitGroup sync.WaitGroup
	for _, csrFilename := range csrFilenames {
		waitGroup.Add(1)
		go func(csrFilename string) {
			defer waitGroup.Done()
			_, err := ca.SignCsrFile(context.Background(), csrFilename, nil, authorize)
			signErrors <- err
		}(csrFilename)
	}
	waitGroup.Wait()
	close(signErrors)
	for err := range signErrors {
		if err != nil {
			t.Errorf("concurrent sign failed: %v", err)
		}
	}

	if maxActiveAuthorize != 2 {
		t.Errorf("authorize calls must overlap (OPA stays out of the CA lock); max concurrent authorize = %d, want 2", maxActiveAuthorize)
	}
}

func TestRsaSignNilAuthorizerFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "name 1"},
	}, privKey)
	if err != nil {
		t.Error(err)
		return
	}
	csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "nil-authorizer.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr,
	}), os.FileMode(0o644)); err != nil {
		t.Error(err)
		return
	}

	_, err = ca.SignCsrFile(context.Background(), csrFilename, nil, nil)
	if !errors.Is(err, caissuingprocess.ErrNilAuthorizer) {
		t.Errorf("expected ErrNilAuthorizer, got %v", err)
	}

	crtDir := filepath.Join(dataDirectory, caId, "data", "crt")
	entries, err := os.ReadDir(crtDir)
	if err != nil {
		t.Error(err)
		return
	}
	if len(entries) != 1 || entries[0].Name() != "1.crt.pem" {
		t.Errorf("nil authorizer must not write a certificate, crt dir: %v", entries)
	}
	if _, err := os.Stat(csrFilename); err != nil {
		t.Errorf("nil authorizer must leave the CSR in the spool: %v", err)
	}
}

func TestRsaRevokeNilAuthorizerFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}

	err = ca.RevokeSerial(context.Background(), big.NewInt(1), nil)
	if !errors.Is(err, caissuingprocess.ErrNilAuthorizer) {
		t.Errorf("expected ErrNilAuthorizer, got %v", err)
	}
}

func TestRsaCreateMissingDataDirectory(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := filepath.Join(t.TempDir(), "not-yet-created", "data")
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}
	if fileInfo, err := os.Stat(dataDirectory); err != nil || !fileInfo.IsDir() {
		t.Errorf("expected the missing data directory to be created, stat=%v err=%v", fileInfo, err)
	}
}

func TestRsaDataDirectoryIsFileFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(dataDirectory, []byte("not a directory"), os.FileMode(0o600)); err != nil {
		t.Error(err)
		return
	}
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	_, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err == nil {
		t.Error("expected an error when the data directory is a file")
		return
	}
	if !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("expected an is-not-a-directory error, got %v", err)
	}
}

func TestRsaInitialCrlExists(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}

	crlBody, err := ca.GetCrlPem()
	if err != nil {
		t.Error(err)
		return
	}
	if len(crlBody) == 0 {
		t.Error("expected the CRL to exist right after loading the CA")
		return
	}
	pemBlock, rest := pem.Decode(crlBody)
	if len(rest) != 0 {
		t.Error("invalid reminder")
		return
	}
	if pemBlock == nil {
		t.Error("no pem block in CRL")
		return
	}
	parseCrl, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	if crlLen := len(parseCrl.RevokedCertificateEntries); crlLen != 0 {
		t.Errorf("expected an empty CRL, got %d revoked entries", crlLen)
	}
}

func TestRsaGetCrlPemReportsMissingFile(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:   12 * time.Hour,
		Validity: testCaValidity,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}

	// A missing CRL file must surface as an error, not as an empty body: the
	// handler answers No Content with it instead of a 200 that a client would
	// read as "nothing is revoked".
	if err := os.Remove(filepath.Join(dataDirectory, caId, "ca.crl.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.GetCrlPem(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected fs.ErrNotExist for a missing CRL file, got %v", err)
	}
}

func TestRsaClockSkewBackdatesValidityTimes(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"
	const clockSkew = 5 * time.Minute

	beforeLoad := time.Now()
	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:    12 * time.Hour,
		Validity:  testCaValidity,
		ClockSkew: clockSkew,
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
		return
	}
	afterLoad := time.Now()

	assertBackdated := func(label string, value time.Time) {
		t.Helper()
		// x509 stores these times truncated to whole seconds, and the real
		// time.Now() at each write sits somewhere between beforeLoad and
		// afterLoad, so allow a small tolerance.
		const tolerance = 2 * time.Second
		if value.Before(beforeLoad.Add(-clockSkew - tolerance)) {
			t.Errorf("%s %s is backdated more than the %s skew", label, value.Format(time.RFC3339), clockSkew)
		}
		if value.After(afterLoad.Add(-clockSkew + tolerance)) {
			t.Errorf("%s %s is not backdated by the %s skew", label, value.Format(time.RFC3339), clockSkew)
		}
	}

	// The root certificate is backdated.
	issuerPem, err := ca.GetIssuerPem()
	if err != nil {
		t.Error(err)
		return
	}
	issuerPemBlock, _ := pem.Decode(issuerPem)
	if issuerPemBlock == nil {
		t.Error("no PEM block in the issuer certificate")
		return
	}
	issuerCertificate, err := x509.ParseCertificate(issuerPemBlock.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	assertBackdated("issuer not_before", issuerCertificate.NotBefore)

	// The CRL ThisUpdate is backdated.
	crlBody, err := ca.GetCrlPem()
	if err != nil {
		t.Error(err)
		return
	}
	crlPemBlock, _ := pem.Decode(crlBody)
	if crlPemBlock == nil {
		t.Error("no PEM block in the CRL")
		return
	}
	parseCrl, err := x509.ParseRevocationList(crlPemBlock.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	assertBackdated("crl this_update", parseCrl.ThisUpdate)

	// An issued certificate is backdated too.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "name 1"},
	}, privKey)
	if err != nil {
		t.Error(err)
		return
	}
	csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "skew.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr,
	}), os.FileMode(0o644)); err != nil {
		t.Error(err)
		return
	}
	signedPem, err := ca.SignCsrFile(context.Background(), csrFilename, nil, func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		return nil
	})
	if err != nil {
		t.Error(err)
		return
	}
	signedPemBlock, _ := pem.Decode(signedPem)
	if signedPemBlock == nil {
		t.Error("no PEM block in the signed certificate")
		return
	}
	signedCertificate, err := x509.ParseCertificate(signedPemBlock.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	assertBackdated("issued not_before", signedCertificate.NotBefore)

	// Reloading with the same skew must not flag the root certificate as
	// changed: the validity window is identical.
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}
}

func newRsaTestCaConfig() types.CertificateAuthorityType {
	return types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "rsa",
			Config: types.KeyTypeRsaConfigType{
				Size: 2048,
			},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
}

func TestRsaCaKeyMismatchFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}

	// A different key of the same size: the key size still matches the
	// configuration, so this is caught by comparing the key with the
	// certificate and nothing else.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}
	caKeyFilename := filepath.Join(dataDirectory, caId, "ca.key.pem")
	if err := os.WriteFile(caKeyFilename, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(otherKey),
	}), os.FileMode(0o600)); err != nil {
		t.Error(err)
		return
	}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); !errors.Is(err, caissuingprocess.ErrCaKeyMismatch) {
		t.Errorf("expected ErrCaKeyMismatch, got %v", err)
	}
}

func TestRsaMissingCaKeyWithExistingCertificateFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}

	caKeyFilename := filepath.Join(dataDirectory, caId, "ca.key.pem")
	if err := os.Remove(caKeyFilename); err != nil {
		t.Error(err)
		return
	}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); !errors.Is(err, caissuingprocess.ErrCaKeyMismatch) {
		t.Errorf("expected ErrCaKeyMismatch, got %v", err)
	}

	// The load is stopped before any key is generated, so the lost key is not
	// replaced by one the operator cannot use.
	if _, err := os.Stat(caKeyFilename); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected no private key to be created, got %v", err)
	}
}

func TestRsaCaKeyMissingAndCertificateMissingBootstraps(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}

	// Only the certificate is gone: the key can still sign for it, so the CA
	// issues its certificate again instead of refusing to start.
	caCertificateFilename := filepath.Join(dataDirectory, caId, "data", "crt", "1.crt.pem")
	if err := os.Remove(caCertificateFilename); err != nil {
		t.Error(err)
		return
	}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
		return
	}
	if _, err := os.Stat(caCertificateFilename); err != nil {
		t.Error(err)
	}
}

// The key a client asks to have certified has to be strong enough for the
// certificate to be worth something, whether or not the policy in front of the
// CA thought to ask about it. P-224 is the one that used to slip through: no
// Go check mentions it and every browser baseline has dropped it.
func TestRsaSignCsrFileSubjectKeyStrength(t *testing.T) {
	logger := &types.StdLogger{}

	rsaKey := func(bits int) crypto.Signer {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Error(err)
			return nil
		}
		return key
	}
	ecdsaKey := func(curve elliptic.Curve) crypto.Signer {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Error(err)
			return nil
		}
		return key
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	tests := []struct {
		name     string
		key      crypto.Signer
		accepted bool
	}{
		{"rsa 1024", rsaKey(1024), false},
		{"rsa 2048", rsaKey(2048), true},
		{"ecdsa P-224", ecdsaKey(elliptic.P224()), false},
		{"ecdsa P-256", ecdsaKey(elliptic.P256()), true},
		{"ed25519", ed25519Key, true},
	}
	for _, test := range tests {
		if test.key == nil {
			return
		}

		dataDirectory := t.TempDir()
		caId := "test_ca_1"
		configData := types.CertificateAuthorityType{
			Subject: types.CertificateAuthoritySubjectType{
				CommonName: "test_ca_1",
			},
			KeyConfig: types.KeyConfigType{
				Type: "rsa",
				Config: types.KeyTypeRsaConfigType{
					Size: 2048,
				},
			},
			CrlTtl:            12 * time.Hour,
			Validity:          testCaValidity,
			PermittedIPRanges: []string{"0.0.0.0/0"},
			ExcludedIPRanges:  []string{"0.0.0.0/0"},
		}
		oneCa, err := caissuingprocess.LoadOneCa(
			context.Background(),
			logger,
			caId,
			dataDirectory,
			configData,
		)
		if err != nil {
			t.Error(err)
			return
		}

		csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "leaf.example.com",
			},
		}, test.key)
		if err != nil {
			t.Error(err)
			return
		}
		csrFilename := filepath.Join(t.TempDir(), "leaf.csr.pem")
		if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrDer,
		}), os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}

		_, err = oneCa.SignCsrFile(
			context.Background(),
			csrFilename,
			nil,
			func(ctx context.Context, proposedCertificate *x509.Certificate) error { return nil },
		)
		if test.accepted {
			if err != nil {
				t.Errorf("%s: expected a certificate, got %v", test.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: expected a refusal, got a certificate", test.name)
			continue
		}
		if !errors.Is(err, types.ErrWeakPublicKey) {
			t.Errorf("%s: expected %v, got %v", test.name, types.ErrWeakPublicKey, err)
		}
	}
}

// revokeTestCa is a loaded CA that has already issued one leaf certificate,
// together with the paths and certificates a test needs to revoke something.
type revokeTestCa struct {
	oneCa          *caissuingprocess.OneCaType
	issuedCertsDir string
	leaf           *x509.Certificate
	caCertificate  *x509.Certificate
}

func newRevokeTestCa(t *testing.T) revokeTestCa {
	t.Helper()
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	oneCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	csrFilename := filepath.Join(t.TempDir(), "leaf.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDer,
	}), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
	leafPemBytes, err := oneCa.SignCsrFile(
		context.Background(),
		csrFilename,
		nil,
		func(ctx context.Context, proposedCertificate *x509.Certificate) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pemhelper.FromPemToCertificate(leafPemBytes)
	if err != nil {
		t.Fatal(err)
	}

	caPemBytes, err := oneCa.GetIssuerPem()
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := pemhelper.FromPemToCertificate(caPemBytes)
	if err != nil {
		t.Fatal(err)
	}

	return revokeTestCa{
		oneCa:          oneCa,
		issuedCertsDir: filepath.Join(dataDirectory, caId, "data", "crt"),
		leaf:           leaf,
		caCertificate:  caCertificate,
	}
}

func revokedSerialsInCrl(t *testing.T, oneCa *caissuingprocess.OneCaType) []*big.Int {
	t.Helper()
	crlBody, err := oneCa.GetCrlPem()
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(crlBody)
	if pemBlock == nil {
		t.Fatal("no pem block in CRL")
	}
	parseCrl, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serials := []*big.Int{}
	for _, entry := range parseCrl.RevokedCertificateEntries {
		serials = append(serials, entry.SerialNumber)
	}
	return serials
}

func allowRevoke(ctx context.Context, issuedCertificate *x509.Certificate) error { return nil }

// The serial in the request names the file to read, so it has to agree with the
// certificate in it. A copy of a certificate under a second name is still a
// certificate of this CA and would verify, so what must be refused is the copy
// putting its own name in the CRL while a policy is asked about that name.
func TestRsaRevokeSerialOfACopyIsRefused(t *testing.T) {
	ca := newRevokeTestCa(t)

	aliasSerial := new(big.Int).Add(ca.leaf.SerialNumber, big.NewInt(1))
	leafPemBytes, err := pemhelper.ToPem(ca.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(ca.issuedCertsDir, aliasSerial.String()+".crt.pem"),
		leafPemBytes,
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}

	askedAbout := []*big.Int{}
	err = ca.oneCa.RevokeSerial(
		context.Background(),
		aliasSerial,
		func(ctx context.Context, issuedCertificate *x509.Certificate) error {
			askedAbout = append(askedAbout, issuedCertificate.SerialNumber)
			return nil
		},
	)
	if !errors.Is(err, caissuingprocess.ErrRevokeSerialMismatch) {
		t.Errorf("expected ErrRevokeSerialMismatch, got %v", err)
	}
	if len(askedAbout) != 0 {
		t.Error("expected the policy not to be asked about a serial that does not match the certificate")
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected an empty CRL, got %v", serials)
	}
}

// x509.Verify accepts the self-signed root as a leaf, because the root is in the
// store it is verified against, so verification alone would let a CA publish a
// CRL revoking itself while still serving the certificate at /issuer.pem.
func TestRsaRevokeTheCaCertificateBySerialIsRefused(t *testing.T) {
	ca := newRevokeTestCa(t)

	// The policy is counted as well as the error checked: refusing the CA
	// certificate is meant to happen before a policy is asked about it, and
	// the CRL index would refuse the same serial later for its own reasons,
	// so the error alone would not say which check did the work.
	asked := 0
	err := ca.oneCa.RevokeSerial(
		context.Background(),
		ca.caCertificate.SerialNumber,
		func(ctx context.Context, issuedCertificate *x509.Certificate) error {
			asked++
			return nil
		},
	)
	if !errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate) {
		t.Errorf("expected ErrCannotRevokeCaCertificate, got %v", err)
	}
	if asked != 0 {
		t.Errorf("expected the policy not to be asked about the CA certificate, got %d calls", asked)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected an empty CRL, got %v", serials)
	}
}

func TestRsaRevokeTheCaCertificateByCertificateIsRefused(t *testing.T) {
	ca := newRevokeTestCa(t)

	asked := 0
	err := ca.oneCa.RevokeCertificate(
		context.Background(),
		ca.caCertificate,
		func(ctx context.Context, issuedCertificate *x509.Certificate) error {
			asked++
			return nil
		},
	)
	if !errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate) {
		t.Errorf("expected ErrCannotRevokeCaCertificate, got %v", err)
	}
	if asked != 0 {
		t.Errorf("expected the policy not to be asked about the CA certificate, got %d calls", asked)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected an empty CRL, got %v", serials)
	}
}

// A certificate of another CA is not one this CA issued, so it does not belong
// in this CA's CRL whichever way it is presented.
func TestRsaRevokeACertificateOfAnotherCaIsRefusedByCertificate(t *testing.T) {
	ca := newRevokeTestCa(t)
	other := newRevokeTestCa(t)

	err := ca.oneCa.RevokeCertificate(context.Background(), other.leaf, allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrCertificateNotIssuedByThisCa) {
		t.Errorf("expected ErrCertificateNotIssuedByThisCa, got %v", err)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected an empty CRL, got %v", serials)
	}
}

func TestRsaRevokeACertificateOfAnotherCaIsRefusedBySerial(t *testing.T) {
	ca := newRevokeTestCa(t)
	other := newRevokeTestCa(t)

	// The serial of the other CA's leaf, filed in this CA's directory: the
	// file exists, so an unknown serial is not the refusal, and the
	// certificate in it is not one this CA issued.
	leafPemBytes, err := pemhelper.ToPem(other.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(ca.issuedCertsDir, other.leaf.SerialNumber.String()+".crt.pem"),
		leafPemBytes,
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}

	err = ca.oneCa.RevokeSerial(context.Background(), other.leaf.SerialNumber, allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrCertificateNotIssuedByThisCa) {
		t.Errorf("expected ErrCertificateNotIssuedByThisCa, got %v", err)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected an empty CRL, got %v", serials)
	}
}

func TestRsaRevokeSerialUnknownSerial(t *testing.T) {
	ca := newRevokeTestCa(t)

	err := ca.oneCa.RevokeSerial(context.Background(), big.NewInt(4242), allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrUnknownSerial) {
		t.Errorf("expected ErrUnknownSerial, got %v", err)
	}
}

// Both paths end in the same place, and the serial that goes into the CRL is
// the one on the certificate, which is the one the policy was asked about.
func TestRsaRevokeSerialRevokes(t *testing.T) {
	ca := newRevokeTestCa(t)

	askedAbout := []*big.Int{}
	err := ca.oneCa.RevokeSerial(
		context.Background(),
		ca.leaf.SerialNumber,
		func(ctx context.Context, issuedCertificate *x509.Certificate) error {
			askedAbout = append(askedAbout, issuedCertificate.SerialNumber)
			return nil
		},
	)
	if err != nil {
		t.Error(err)
		return
	}
	if len(askedAbout) != 1 || askedAbout[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the policy to be asked about %s, got %v", ca.leaf.SerialNumber, askedAbout)
	}
	serials := revokedSerialsInCrl(t, ca.oneCa)
	if len(serials) != 1 || serials[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the CRL to revoke %s, got %v", ca.leaf.SerialNumber, serials)
	}
}

func TestRsaRevokeCertificateRevokes(t *testing.T) {
	ca := newRevokeTestCa(t)

	askedAbout := []*big.Int{}
	err := ca.oneCa.RevokeCertificate(
		context.Background(),
		ca.leaf,
		func(ctx context.Context, issuedCertificate *x509.Certificate) error {
			askedAbout = append(askedAbout, issuedCertificate.SerialNumber)
			return nil
		},
	)
	if err != nil {
		t.Error(err)
		return
	}
	if len(askedAbout) != 1 || askedAbout[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the policy to be asked about %s, got %v", ca.leaf.SerialNumber, askedAbout)
	}
	serials := revokedSerialsInCrl(t, ca.oneCa)
	if len(serials) != 1 || serials[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the CRL to revoke %s, got %v", ca.leaf.SerialNumber, serials)
	}
}

func TestRsaRevokeCertificateNilCertificate(t *testing.T) {
	ca := newRevokeTestCa(t)

	err := ca.oneCa.RevokeCertificate(context.Background(), nil, allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrCertificateNotIssuedByThisCa) {
		t.Errorf("expected ErrCertificateNotIssuedByThisCa, got %v", err)
	}
}

func TestRsaRevokeCertificateNilAuthorizerFails(t *testing.T) {
	ca := newRevokeTestCa(t)

	err := ca.oneCa.RevokeCertificate(context.Background(), ca.leaf, nil)
	if !errors.Is(err, caissuingprocess.ErrNilAuthorizer) {
		t.Errorf("expected ErrNilAuthorizer, got %v", err)
	}
}

func TestRsaRevokeSerialNilSerial(t *testing.T) {
	ca := newRevokeTestCa(t)

	err := ca.oneCa.RevokeSerial(context.Background(), nil, allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrUnknownSerial) {
		t.Errorf("expected ErrUnknownSerial, got %v", err)
	}
}

// revocationStaysMillis is a revocation_expires_at far enough ahead that a test
// about something else does not accidentally become a test about pruning.
const revocationStaysMillis = 4102444800000 // 2100-01-01T00:00:00Z

// The CRL index is a file in the data directory that entries are added to
// without going through either revoking path, so it is checked on the way into
// the CRL: a serial added by hand cannot be this CA's own.
func TestRsaCrlIndexWithTheCaSerialIsRefused(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	if err := os.WriteFile(crlIndexFilename, []byte(
		"- serial_number: \""+ca.caCertificate.SerialNumber.String()+"\"\n"+
			"  revocation_time: 1714575000000\n"+
			"  revocation_expires_at: "+strconv.FormatInt(revocationStaysMillis, 10)+"\n",
	), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	err := ca.oneCa.UpdateCrl()
	if !errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate) {
		t.Errorf("expected ErrCannotRevokeCaCertificate, got %v", err)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected the published CRL to be left without the entry, got %v", serials)
	}
}

// A serial in the index that is not the CA's own is left alone: it names no
// certificate, so it cannot mislead anyone into distrusting one, and an
// operator keeping the index by hand is not the threat the CA certificate is.
func TestRsaCrlIndexWithAnUnissuedSerialIsKept(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	unissued := new(big.Int).Add(ca.leaf.SerialNumber, big.NewInt(7))
	if err := os.WriteFile(crlIndexFilename, []byte(
		"- serial_number: \""+unissued.String()+"\"\n"+
			"  revocation_time: 1714575000000\n"+
			"  revocation_expires_at: "+strconv.FormatInt(revocationStaysMillis, 10)+"\n",
	), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	if err := ca.oneCa.UpdateCrl(); err != nil {
		t.Fatal(err)
	}
	serials := revokedSerialsInCrl(t, ca.oneCa)
	if len(serials) != 1 || serials[0].Cmp(unissued) != 0 {
		t.Errorf("expected the CRL to revoke %s, got %v", unissued, serials)
	}
}

// The index is written only once the CRL it describes has been issued, so a
// CRL that cannot be built leaves crl.yml exactly as it was. This is the shape
// writing the index first produced: an entry the CA refused was rewritten onto
// disk by the step that then refused it, so every later load read the refusal
// back and the CA could not start until the index was edited by hand.
func TestRsaCrlIndexIsLeftAloneWhenTheCrlIsNotIssued(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	seeded := []byte(
		"- serial_number: \"" + ca.caCertificate.SerialNumber.String() + "\"\n" +
			"  revocation_time: 1714575000000\n" +
			"  revocation_expires_at: " + strconv.FormatInt(revocationStaysMillis, 10) + "\n",
	)
	if err := os.WriteFile(crlIndexFilename, seeded, os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	err := ca.oneCa.UpdateCrl()
	if !errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate) {
		t.Fatalf("expected ErrCannotRevokeCaCertificate, got %v", err)
	}

	after, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(seeded) {
		t.Errorf("the index must not be rewritten when no CRL was issued:\n before: %q\n after:  %q", seeded, after)
	}
}

// A revocation that cannot become a CRL must not reach the index either: the
// serial is appended in memory, an entry already in the index is rejected, and
// the file keeps only what it had. Writing the index first persisted the
// append before the rejection, so the index named a revocation the CA had
// never published.
func TestRsaCrlIndexKeepsNoEntryForARevocationTheCrlRefused(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	seeded := []byte(
		"- serial_number: \"" + ca.caCertificate.SerialNumber.String() + "\"\n" +
			"  revocation_time: 1714575000000\n" +
			"  revocation_expires_at: " + strconv.FormatInt(revocationStaysMillis, 10) + "\n",
	)
	if err := os.WriteFile(crlIndexFilename, seeded, os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	err := ca.oneCa.RevokeSerial(context.Background(), ca.leaf.SerialNumber, allowRevoke)
	if !errors.Is(err, caissuingprocess.ErrCannotRevokeCaCertificate) {
		t.Fatalf("expected ErrCannotRevokeCaCertificate, got %v", err)
	}

	index, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(index), ca.leaf.SerialNumber.String()) {
		t.Errorf("the index must not name a revocation no CRL was issued for:\n%s", index)
	}
}

// The moved write is still there: on the path that succeeds, the index records
// the serial the CRL was just shown to revoke.
func TestRsaCrlIndexRecordsARevocationThatWasIssued(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	if err := ca.oneCa.RevokeSerial(context.Background(), ca.leaf.SerialNumber, allowRevoke); err != nil {
		t.Fatal(err)
	}

	index, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), ca.leaf.SerialNumber.String()) {
		t.Errorf("the index should record the revoked serial %s:\n%s", ca.leaf.SerialNumber, index)
	}
	serials := revokedSerialsInCrl(t, ca.oneCa)
	if len(serials) != 1 || serials[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the CRL to revoke %s, got %v", ca.leaf.SerialNumber, serials)
	}
}

// crlIndexEntry mirrors the index schema so a test can read the file the CA
// wrote, comment prefix and all.
type crlIndexEntry struct {
	SerialNumber        *big.Int `yaml:"serial_number"`
	RevocationTime      int64    `yaml:"revocation_time"`
	RevocationExpiresAt int64    `yaml:"revocation_expires_at"`
}

func readCrlIndexEntries(t *testing.T, crlIndexFilename string) []crlIndexEntry {
	t.Helper()
	content, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		t.Fatal(err)
	}
	var entries []crlIndexEntry
	if err := yaml.Unmarshal(content, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

// A revocation records when it stops mattering, so the entry can leave the list
// on its own: the certificate's own notAfter, which issuance already caps at
// the CA's.
func TestRsaRevocationRecordsTheCertificateExpiry(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	if err := ca.oneCa.RevokeSerial(context.Background(), ca.leaf.SerialNumber, allowRevoke); err != nil {
		t.Fatal(err)
	}

	entries := readCrlIndexEntries(t, crlIndexFilename)
	if len(entries) != 1 {
		t.Fatalf("expected one index entry, got %d", len(entries))
	}
	if wantExpiresAt := ca.leaf.NotAfter.UnixMilli(); entries[0].RevocationExpiresAt != wantExpiresAt {
		t.Errorf("revocation_expires_at = %d, want the certificate's notAfter %d", entries[0].RevocationExpiresAt, wantExpiresAt)
	}
}

// Once the certificate a revocation names can no longer be valid, the entry
// leaves the list: a verifier rejects the expired certificate on its own, so
// keeping the entry only makes the CRL grow. It leaves the index too.
func TestRsaCrlIndexPrunesAnExpiredRevocation(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	longExpired := time.Now().Add(-time.Hour).UnixMilli()
	if err := os.WriteFile(crlIndexFilename, []byte(
		"- serial_number: \"999123\"\n"+
			"  revocation_time: 1714575000000\n"+
			"  revocation_expires_at: "+strconv.FormatInt(longExpired, 10)+"\n",
	), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	if err := ca.oneCa.UpdateCrl(); err != nil {
		t.Fatal(err)
	}
	if serials := revokedSerialsInCrl(t, ca.oneCa); len(serials) != 0 {
		t.Errorf("expected the expired revocation to leave the CRL, got %v", serials)
	}
	if entries := readCrlIndexEntries(t, crlIndexFilename); len(entries) != 0 {
		t.Errorf("expected the expired revocation to leave the index, got %v", entries)
	}
}

// An entry an operator wrote has to say when it stops mattering: without it
// there is nothing to prune against, and guessing would either drop a live
// revocation or keep a dead one forever.
func TestRsaCrlIndexRefusesAnEntryWithNoExpiry(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	if err := os.WriteFile(crlIndexFilename, []byte(
		"- serial_number: \"999123\"\n"+
			"  revocation_time: 1714575000000\n",
	), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	err := ca.oneCa.UpdateCrl()
	if !errors.Is(err, caissuingprocess.ErrInvalidCrlIndex) {
		t.Fatalf("expected ErrInvalidCrlIndex, got %v", err)
	}
	if !strings.Contains(err.Error(), "revocation_expires_at") {
		t.Errorf("expected the report to name revocation_expires_at, got %v", err)
	}
}

// An entry appended under the empty index is not a second entry: yaml sees only
// the first document, so reading it as one used to discard the appended line,
// rewrite the index without it, and publish a CRL with no revocation and no
// error. It is refused now, by name, and the file is left as it was.
func TestRsaCrlIndexRefusesAnEntryAppendedUnderTheEmptyIndex(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	seeded := []byte(
		"[]\n" +
			"- serial_number: \"999123\"\n" +
			"  revocation_time: 1714575000000\n" +
			"  revocation_expires_at: " + strconv.FormatInt(revocationStaysMillis, 10) + "\n",
	)
	if err := os.WriteFile(crlIndexFilename, seeded, os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	err := ca.oneCa.UpdateCrl()
	if !errors.Is(err, caissuingprocess.ErrInvalidCrlIndex) {
		t.Fatalf("expected ErrInvalidCrlIndex, got %v", err)
	}
	after, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(seeded) {
		t.Errorf("a refused index must be left as it was:\n before: %q\n after:  %q", seeded, after)
	}
}

// A second YAML document is not an index either: yaml.Unmarshal read the first
// and left the rest, which is the same silent loss in another shape.
func TestRsaCrlIndexRefusesASecondDocument(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlIndexFilename := filepath.Join(filepath.Dir(ca.issuedCertsDir), "crl.yml")

	if err := os.WriteFile(crlIndexFilename, []byte(
		"[]\n---\n- serial_number: \"999123\"\n"+
			"  revocation_time: 1714575000000\n"+
			"  revocation_expires_at: "+strconv.FormatInt(revocationStaysMillis, 10)+"\n",
	), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	if err := ca.oneCa.UpdateCrl(); !errors.Is(err, caissuingprocess.ErrInvalidCrlIndex) {
		t.Fatalf("expected ErrInvalidCrlIndex, got %v", err)
	}
}

// capturingLogger is a logger that keeps its output, so a test can assert what
// the CA reported about a spool entry it skipped.
func capturingLogger() (types.Logger, *bytes.Buffer) {
	var logOutput bytes.Buffer
	logger := types.NewStdLogger(slog.New(types.NewLogHandler(
		slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)))
	return logger, &logOutput
}

func allowSign(ctx context.Context, proposedCertificate *x509.Certificate) error {
	return nil
}

// A ca.crl.pem no parser can read is replaced, not read: the next CRL takes its
// number from the clock and the revocations the index holds come back in the
// file. Reading the old CRL to number the new one is what made a corrupt file
// refuse every load, of the very artifact this call rewrites.
func TestRsaCorruptCrlIsReplacedInsteadOfRead(t *testing.T) {
	ca := newRevokeTestCa(t)
	crlFilename := filepath.Join(filepath.Dir(filepath.Dir(ca.issuedCertsDir)), "ca.crl.pem")

	if err := ca.oneCa.RevokeSerial(context.Background(), ca.leaf.SerialNumber, allowRevoke); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crlFilename, []byte("{{{ this is not a crl\n"), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	if err := ca.oneCa.UpdateCrl(); err != nil {
		t.Fatalf("a corrupt CRL must be replaced, not read: %v", err)
	}
	serials := revokedSerialsInCrl(t, ca.oneCa)
	if len(serials) != 1 || serials[0].Cmp(ca.leaf.SerialNumber) != 0 {
		t.Errorf("expected the replacement CRL to revoke %s, got %v", ca.leaf.SerialNumber, serials)
	}
}

func loadCaWithLogger(t *testing.T, logger types.Logger) (*caissuingprocess.OneCaType, string) {
	t.Helper()
	dataDirectory := t.TempDir()
	oneCa, err := caissuingprocess.LoadOneCa(context.Background(), logger, "test_ca_1", dataDirectory, newRsaTestCaConfig())
	if err != nil {
		t.Fatal(err)
	}
	return oneCa, dataDirectory
}

// A spool entry larger than any CSR is skipped before it is read: the spool is
// a drop box, and one enormous file in it must not decide how much memory a
// run uses. The HTTP path caps a sign request at the same size.
func TestRsaCsrSpoolSkipsAnEntryLargerThanACsr(t *testing.T) {
	logger, logOutput := capturingLogger()
	oneCa, dataDirectory := loadCaWithLogger(t, logger)

	bigFilename := filepath.Join(dataDirectory, "test_ca_1", "data", "csr", "big.csr.pem")
	if err := os.WriteFile(bigFilename, make([]byte, 32*1024+1), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	if err := oneCa.IssueAllCsrInQueue(context.Background(), allowSign); err != nil {
		t.Fatalf("an oversized entry must be skipped, not fail the queue: %v", err)
	}
	if !strings.Contains(logOutput.String(), "larger than a CSR can be") {
		t.Errorf("expected the oversized entry to be reported, got:\n%s", logOutput.String())
	}
	if _, err := os.Stat(bigFilename); err != nil {
		t.Errorf("a skipped entry must be left where it is: %v", err)
	}
}

func loadSigningTestCa(t *testing.T) (*caissuingprocess.OneCaType, string, string) {
	t.Helper()
	logger := &types.StdLogger{}
	dataDirectory := t.TempDir()
	caId := "test_ca_1"
	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
	}
	oneCa, err := caissuingprocess.LoadOneCa(context.Background(), logger, caId, dataDirectory, configData)
	if err != nil {
		t.Fatal(err)
	}
	return oneCa, dataDirectory, caId
}

func TestRsaMalformedBasicConstraintsRefusedBeforeAuthorize(t *testing.T) {
	oneCa, dataDirectory, caId := loadSigningTestCa(t)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "sub-ca.example.com"},
		ExtraExtensions: []pkix.Extension{
			// CA:TRUE plus trailing byte: provisional parse must fail closed.
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff, 0x00}},
		},
	}, privKey)
	if err != nil {
		t.Fatal(err)
	}
	csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "malformed-bc.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDer,
	}), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	authorizeCalls := 0
	_, err = oneCa.SignCsrFile(context.Background(), csrFilename, nil, func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		authorizeCalls++
		return nil
	})
	if !errors.Is(err, caissuingprocess.ErrInvalidCsr) {
		t.Fatalf("expected ErrInvalidCsr, got %v", err)
	}
	if authorizeCalls != 0 {
		t.Fatalf("authorize must not run for malformed basicConstraints, got %d calls", authorizeCalls)
	}
	crtDir := filepath.Join(dataDirectory, caId, "data", "crt")
	entries, err := os.ReadDir(crtDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "1.crt.pem" {
		t.Fatalf("malformed BC must not write a leaf certificate, crt dir: %v", entries)
	}
}

func TestRsaLeafKeyCertSignRefused(t *testing.T) {
	oneCa, dataDirectory, caId := loadSigningTestCa(t)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com"},
		ExtraExtensions: []pkix.Extension{
			// keyCertSign | cRLSign (same encoding as the CA-true fixtures).
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x01, 0x06}},
		},
	}, privKey)
	if err != nil {
		t.Fatal(err)
	}
	csrFilename := filepath.Join(dataDirectory, caId, "data", "csr", "leaf-certsign.csr.pem")
	if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDer,
	}), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}

	_, err = oneCa.SignCsrFile(context.Background(), csrFilename, nil, func(ctx context.Context, proposedCertificate *x509.Certificate) error {
		return nil
	})
	if !errors.Is(err, caissuingprocess.ErrInvalidCsr) {
		t.Fatalf("leaf with keyCertSign must be ErrInvalidCsr, got %v", err)
	}
}
