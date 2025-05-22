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
			PermittedIPRanges: []string{"0.0.0.0/0"},
			ExcludedIPRanges:  []string{"INVALIDME"},
		},
	); err != nil {
	} else {
		t.Error("Expected error")
	}
}

func TestEcdsaInvalidCsrKey(t *testing.T) {
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

	if err := ca.IssueAllCsrInQueue(); err != nil {
		if !errors.Is(err, types.ErrInvalidKeyTypeInCsr) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
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
	); err != nil {
		if !errors.Is(err, types.ErrUnsupportedChangeToCurve) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
	}
}
