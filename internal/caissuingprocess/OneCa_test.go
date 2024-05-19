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
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestOneCaBootstrap(t *testing.T) {
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
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
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

		log.Println(csrFilename)
		if err := os.WriteFile(csrFilename, csrAsPem, os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}
	}

	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Error(err)
	}
}

func TestInvalidCaIdOnlyDot(t *testing.T) {
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		".",
		t.TempDir(),
		types.CertificateAuthorityType{},
	); err != nil {
		if !errors.Is(err, caissuingprocess.ErrInvalidCaId) {
			t.Error(err)
		}
	} else {
		t.Error("expected error")
	}
}
func TestInvalidCaIdWithSlash(t *testing.T) {
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		"/ok",
		t.TempDir(),
		types.CertificateAuthorityType{},
	); err != nil {
		if !errors.Is(err, caissuingprocess.ErrInvalidCaId) {
			t.Error(err)
		}
	} else {
		t.Error("expected error")
	}
}

func TestInvalidPermittedIPRanges(t *testing.T) {
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
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
			PermittedIPRanges: []string{"INVALIDME"},
			ExcludedIPRanges:  []string{"0.0.0.0/0"},
		},
	); err != nil {
	} else {
		t.Error("Expected error")
	}
}

func TestInvalidExcludedIPRanges(t *testing.T) {
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
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
			PermittedIPRanges: []string{"0.0.0.0/0"},
			ExcludedIPRanges:  []string{"INVALIDME"},
		},
	); err != nil {
	} else {
		t.Error("Expected error")
	}
}

func TestInvalidCsrKey(t *testing.T) {
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
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
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

		log.Println(csrFilename)
		if err := os.WriteFile(csrFilename, csrAsPem, os.FileMode(0o644)); err != nil {
			t.Error(err)
			return
		}
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Error(err)
	}

	if err := ca.IssueAllCsrInQueue(); err != nil {
		if !errors.Is(err, caissuingprocess.ErrInvalidKeyTypeInCsr) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
	}
}

func TestChangedKeySize(t *testing.T) {
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
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
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
		caId,
		dataDirectory,
		configData,
	); err != nil {
		if !errors.Is(err, caissuingprocess.ErrUnsupportedChangeToKeySize) {
			t.Error(err)
		}
	} else {
		t.Error("expected an error")
	}
}
