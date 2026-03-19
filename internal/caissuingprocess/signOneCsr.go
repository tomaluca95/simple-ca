package caissuingprocess

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

var ErrInvalidCsr = errors.New("invalid csr")

func signOneCsr(
	logger types.Logger,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
	csrFilename string,
	issuedCertificatesDir string,
) ([]byte, error) {
	csrFileContent, err := os.ReadFile(csrFilename)
	if err != nil {
		return nil, err
	}
	csr, err := pemhelper.FromPemToCertificateRequest(csrFileContent)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCsr, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: invalid CSR signature: %v", ErrInvalidCsr, err)
	}

	logger.Debug("Loading CSR: %s", csr.Subject.String())

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial: %w", err)
	}
	if serialNumber.Sign() == 0 {
		return nil, fmt.Errorf("generated invalid certificate serial: zero")
	}

	if csr.PublicKey == nil {
		return nil, fmt.Errorf("%w: %w: %T", ErrInvalidCsr, types.ErrInvalidKeyTypeInCsr, csr.PublicKey)
	}
	crtTemplate := &x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),

		// Mirror CSR-provided metadata/extensions so policy validation can decide
		// whether the resulting certificate is acceptable for this CA.
		Version:         csr.Version,
		Extensions:      append(csr.Extensions, csr.ExtraExtensions...),
		ExtraExtensions: append(csr.Extensions, csr.ExtraExtensions...),
		DNSNames:        csr.DNSNames,
		EmailAddresses:  csr.EmailAddresses,
		IPAddresses:     csr.IPAddresses,
		URIs:            csr.URIs,
	}
	if err := validateCertificateTemplateAgainstCa(crtTemplate, caCertificate, csr.PublicKey, caPrivateKey); err != nil {
		return nil, err
	}

	pemBlock, err := certificateCreateNew(
		logger,
		issuedCertificatesDir,
		crtTemplate,
		caCertificate,
		csr.PublicKey,
		caPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	if err := os.Remove(csrFilename); err != nil {
		return nil, err
	}

	return pemBlock, nil
}

func validateCertificateTemplateAgainstCa(
	crtTemplate *x509.Certificate,
	caCertificate *x509.Certificate,
	csrPublicKey any,
	caPrivateKey crypto.Signer,
) error {
	derBytes, err := x509.CreateCertificate(
		cryptorand.Reader,
		crtTemplate,
		caCertificate,
		csrPublicKey,
		caPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid certificate template for this CA: %v", ErrInvalidCsr, err)
	}
	issuedCertificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("unable to parse generated certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	verifyAt := issuedCertificate.NotBefore
	if verifyAt.IsZero() {
		verifyAt = time.Now()
	}
	if _, err := issuedCertificate.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: verifyAt,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("%w: certificate is not valid against issuer CA constraints: %v", ErrInvalidCsr, err)
	}
	return nil
}
