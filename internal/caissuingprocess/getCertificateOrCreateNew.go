package caissuingprocess

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
)

func getCertificateOrCreateNew(
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	newCertificatePublicKey *rsa.PublicKey,
	caPrivateKey *rsa.PrivateKey,
) (*x509.Certificate, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	if _, err := os.Stat(certificateFilename); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		if _, err := certificateCreateNew(
			issuedCertificatesDir,
			templateCertificate,
			caCertificate,
			newCertificatePublicKey,
			caPrivateKey,
		); err != nil {
			return nil, err
		}
	}

	log.Println("Reading file " + certificateFilename)
	certificateContent, err := os.ReadFile(certificateFilename)
	if err != nil {
		return nil, err
	}
	return pemhelper.FromPemToCertificate(certificateContent)
}

func certificateCreateNew(
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	newCertificatePublicKey *rsa.PublicKey,
	caPrivateKey *rsa.PrivateKey,
) ([]byte, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	if _, err := os.Stat(certificateFilename); err == nil {
		return nil, fmt.Errorf("file %s exists", certificateFilename)
	}

	log.Println("Generate new file for " + certificateFilename)
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
