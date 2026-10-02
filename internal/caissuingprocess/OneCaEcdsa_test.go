package caissuingprocess_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestEcdsaOneCaBootstrap(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "ecdsa",
			Config: types.KeyTypeEcdsaConfigType{
				CurveName: "P-256",
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

func TestEcdsaInvalidCaIdOnlyDot(t *testing.T) {
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
func TestEcdsaInvalidCaIdWithSlash(t *testing.T) {
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

func TestEcdsaInvalidPermittedIPRanges(t *testing.T) {
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
				Type: "ecdsa",
				Config: types.KeyTypeEcdsaConfigType{
					CurveName: "P-256",
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

func TestEcdsaInvalidExcludedIPRanges(t *testing.T) {
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
				Type: "ecdsa",
				Config: types.KeyTypeEcdsaConfigType{
					CurveName: "P-256",
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

func TestEcdsaSupportsEcdsaCsr(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},

		KeyConfig: types.KeyConfigType{
			Type: "ecdsa",
			Config: types.KeyTypeEcdsaConfigType{
				CurveName: "P-256",
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

func TestEcdsaChangedKeySize(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "ecdsa",
			Config: types.KeyTypeEcdsaConfigType{
				CurveName: "P-256",
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

	// Another approved curve: changing the curve of a CA that already has a
	// key is refused, which is a different refusal from a curve this CA does
	// not accept at all.
	configData.KeyConfig = types.KeyConfigType{
		Type: "ecdsa",
		Config: types.KeyTypeEcdsaConfigType{
			CurveName: "P-521",
		},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); err != nil {
		if !errors.Is(err, types.ErrUnsupportedChangeToCurve) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
	}
}

func TestEcdsaCaKeyMismatchFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "ecdsa",
			Config: types.KeyTypeEcdsaConfigType{
				CurveName: "P-256",
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
		return
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	otherKeyDer, err := x509.MarshalECPrivateKey(otherKey)
	if err != nil {
		t.Error(err)
		return
	}
	caKeyFilename := filepath.Join(dataDirectory, caId, "ca.key.pem")
	if err := os.WriteFile(caKeyFilename, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: otherKeyDer,
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

// A CA left on a key an earlier release accepted is refused at load time. The
// key and the certificate in the data directory here are a real, matching pair
// and the certificate differs from the one the tool wrote in nothing but its
// key, so nothing here but the curve is wrong: before the key was measured,
// this CA loaded and signed.
func TestEcdsaCaKeyOnAnUnapprovedCurveFails(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type: "ecdsa",
			Config: types.KeyTypeEcdsaConfigType{
				CurveName: "P-256",
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
		return
	}

	weakKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	weakKeyDer, err := x509.MarshalECPrivateKey(weakKey)
	if err != nil {
		t.Error(err)
		return
	}
	if err := os.WriteFile(
		filepath.Join(dataDirectory, caId, "ca.key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: weakKeyDer}),
		os.FileMode(0o600),
	); err != nil {
		t.Error(err)
		return
	}

	// The certificate is re-signed with the weak key and the template of the
	// one the tool wrote, so it keeps the subject, the validity and every
	// extension the configuration asks for, and the key still matches it.
	caCertificateFilename := filepath.Join(dataDirectory, caId, "data", "crt", "1.crt.pem")
	caCertificateContent, err := os.ReadFile(caCertificateFilename)
	if err != nil {
		t.Error(err)
		return
	}
	caCertificateBlock, _ := pem.Decode(caCertificateContent)
	if caCertificateBlock == nil {
		t.Error("no pem block in the CA certificate")
		return
	}
	caCertificate, err := x509.ParseCertificate(caCertificateBlock.Bytes)
	if err != nil {
		t.Error(err)
		return
	}
	caCertificateDer, err := x509.CreateCertificate(
		rand.Reader,
		caCertificate,
		// The parent carries the issuer name and nothing else: the signing
		// key is the weak one, not the key the old certificate names.
		&x509.Certificate{Subject: caCertificate.Issuer},
		&weakKey.PublicKey,
		weakKey,
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err := os.WriteFile(
		caCertificateFilename,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertificateDer}),
		os.FileMode(0o644),
	); err != nil {
		t.Error(err)
		return
	}

	// The configuration an operator upgrading this CA still has, naming the
	// curve its key is really on.
	configData.KeyConfig = types.KeyConfigType{
		Type: "ecdsa",
		Config: types.KeyTypeEcdsaConfigType{
			CurveName: "P-224",
		},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	); !errors.Is(err, types.ErrWeakPublicKey) {
		t.Errorf("expected ErrWeakPublicKey, got %v", err)
	}
}
