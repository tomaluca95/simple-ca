package caissuingprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func getCertificateOrCreateNewSelfSigned(
	logger types.Logger,
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
) (*x509.Certificate, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	if _, err := os.Stat(certificateFilename); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		if _, err := certificateCreateNew(
			logger,
			issuedCertificatesDir,
			templateCertificate,
			caCertificate,
			extractPublicKeyFromSigner(caPrivateKey),
			caPrivateKey,
		); err != nil {
			return nil, err
		}
	} else {
		logger.Debug("File %s exists", certificateFilename)
	}

	logger.Debug("Reading file %s", certificateFilename)
	certificateContent, err := os.ReadFile(certificateFilename)
	if err != nil {
		return nil, err
	}
	return pemhelper.FromPemToCertificate(certificateContent)
}

func certificateCreateNew(
	logger types.Logger,
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	newCertificatePublicKey any,
	caPrivateKey crypto.Signer,
) ([]byte, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	if _, err := os.Stat(certificateFilename); err == nil {
		return nil, fmt.Errorf("file %s exists", certificateFilename)
	}

	logger.Debug("Generate new file for %s", certificateFilename)
	caDerBytes, err := x509.CreateCertificate(
		rand.Reader,
		templateCertificate,
		caCertificate,
		newCertificatePublicKey,
		caPrivateKey,
	)
	if err != nil {
		return nil, err
	}
	createdCert, err := x509.ParseCertificate(caDerBytes)
	if err != nil {
		return nil, err
	}

	pemBytes, err := pemhelper.ToPem(createdCert)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certificateFilename, pemBytes, os.FileMode(0o644)); err != nil {
		return nil, err
	}
	return pemBytes, nil
}
