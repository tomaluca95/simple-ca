package caissuingprocess

import (
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

var ErrInvalidCsr = errors.New("invalid csr")
var ErrInvalidLifetime = errors.New("invalid certificate lifetime")
var ErrNilAuthorizer = errors.New("nil authorizer")
var ErrCertificateFileExists = errors.New("certificate file exists")
var ErrCertificateNotIssuedByThisCa = errors.New("certificate was not issued by this CA")
var ErrCannotRevokeCaCertificate = errors.New("the CA certificate itself cannot be revoked")

const defaultLifetime = time.Hour

type SignAuthorizer func(ctx context.Context, proposedCertificate *x509.Certificate) error

func signOneCsr(
	ctx context.Context,
	logger types.Logger,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
	csrFilename string,
	notAfter *time.Time,
	clockSkew time.Duration,
	authorize SignAuthorizer,
) (*x509.Certificate, []byte, error) {
	if authorize == nil {
		return nil, nil, ErrNilAuthorizer
	}

	csrFileContent, err := os.ReadFile(csrFilename)
	if err != nil {
		return nil, nil, err
	}
	csr, err := pemhelper.FromPemToCertificateRequest(csrFileContent)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCsr, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid CSR signature: %v", ErrInvalidCsr, err)
	}

	logger.DebugContext(ctx, "loading CSR", "subject", csr.Subject.String())

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate serial: %w", err)
	}
	if serialNumber.Sign() == 0 {
		return nil, nil, fmt.Errorf("generated invalid certificate serial: zero")
	}

	if csr.PublicKey == nil {
		return nil, nil, fmt.Errorf("%w: %w: %T", ErrInvalidCsr, types.ErrInvalidKeyTypeInCsr, csr.PublicKey)
	}

	// The CSR signature has been checked by now, so the key is what the
	// client says it is, and a client asking for a certificate for a key
	// below the accepted minimum is refused here rather than in the policy:
	// a policy that forgets to ask is still a CA that refuses it.
	if err := types.PublicKeyIsAccepted(csr.PublicKey); err != nil {
		return nil, nil, fmt.Errorf("%w: subject key: %w", ErrInvalidCsr, err)
	}

	issuedAt := time.Now()
	notAfterValue := issuedAt.Add(defaultLifetime)
	if notAfter != nil {
		notAfterValue = notAfter.UTC()
	}
	if notAfterValue.After(caCertificate.NotAfter) {
		logger.InfoContext(ctx,
			"capping requested notAfter to the CA notAfter",
			"requested_not_after", notAfterValue,
			"ca_not_after", caCertificate.NotAfter,
		)
		notAfterValue = caCertificate.NotAfter
	}
	if !notAfterValue.After(issuedAt) {
		return nil, nil, fmt.Errorf("%w: requested notAfter %s is not in the future", ErrInvalidLifetime, notAfterValue.Format(time.RFC3339))
	}

	crtTemplate := &x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: serialNumber,
		NotBefore:    issuedAt.Add(-clockSkew),
		NotAfter:     notAfterValue,

		ExtraExtensions: append(csr.Extensions, csr.ExtraExtensions...),
		DNSNames:        csr.DNSNames,
		EmailAddresses:  csr.EmailAddresses,
		IPAddresses:     csr.IPAddresses,
		URIs:            csr.URIs,
	}

	// Authorize the proposed leaf/CA before touching the CA private key, so a
	// denied request never burns a signature. Authorize again after signing so
	// the policy still sees the artifact that will be persisted (Go may add
	// SKI/AKI and similar when CreateCertificate runs).
	provisional, err := provisionalCertificateForAuthorization(crtTemplate, csr.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if err := authorize(ctx, provisional); err != nil {
		return nil, nil, err
	}

	proposedCertificate, pemBytes, err := createAndValidateCertificate(
		ctx,
		logger,
		crtTemplate,
		caCertificate,
		csr.PublicKey,
		caPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	if proposedCertificate.IsCA != provisional.IsCA {
		return nil, nil, fmt.Errorf(
			"%w: basicConstraints disagree between provisional (is_ca=%t) and issued certificate (is_ca=%t)",
			ErrInvalidCsr,
			provisional.IsCA,
			proposedCertificate.IsCA,
		)
	}

	if err := authorize(ctx, proposedCertificate); err != nil {
		return nil, nil, err
	}

	return proposedCertificate, pemBytes, nil
}

func createAndValidateCertificate(
	ctx context.Context,
	logger types.Logger,
	crtTemplate *x509.Certificate,
	caCertificate *x509.Certificate,
	newCertificatePublicKey any,
	caPrivateKey crypto.Signer,
) (*x509.Certificate, []byte, error) {
	derBytes, err := x509.CreateCertificate(
		cryptorand.Reader,
		crtTemplate,
		caCertificate,
		newCertificatePublicKey,
		caPrivateKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid certificate template for this CA: %v", ErrInvalidCsr, err)
	}
	issuedCertificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse generated certificate: %w", err)
	}

	if !issuedCertificate.IsCA {
		forbiddenLeafUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if issuedCertificate.KeyUsage&forbiddenLeafUsage != 0 {
			return nil, nil, fmt.Errorf(
				"%w: leaf certificate must not carry keyCertSign or cRLSign",
				ErrInvalidCsr,
			)
		}
	}

	if err := validateCertificateAgainstCa(issuedCertificate, caCertificate); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidCsr, err)
	}

	pemBytes, err := pemhelper.ToPem(issuedCertificate)
	if err != nil {
		return nil, nil, err
	}
	logger.DebugContext(ctx, "prepared certificate, pending authorization", "serial", issuedCertificate.SerialNumber.String())
	return issuedCertificate, pemBytes, nil
}

// validateCertificateAgainstCa reports whether a certificate is one this CA
// issued and would accept as valid. It says nothing about what the caller may do
// with the certificate, so each caller wraps it with the error of its own path:
// signing answers "invalid CSR" and revoking answers something else, and the
// difference is the caller's, not the verification's.
func validateCertificateAgainstCa(
	issuedCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
) error {
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
		return fmt.Errorf("certificate is not valid against issuer CA constraints: %v", err)
	}
	return nil
}

// certificateIsRevocable decides whether a certificate may be added to this
// CA's CRL, before the policy is asked and before anything is written.
//
// Two things are refused, and neither is a side effect of the verification
// above:
//
//   - The CA's own certificate. x509.Verify accepts the self-signed root as a
//     leaf, because the root is in the trust store it is verified against, so
//     verification alone would let a CA publish a CRL revoking itself and keep
//     serving the certificate at /issuer.pem.
//   - A certificate this CA did not issue, so a serial from another CA, or from
//     no CA at all, cannot end up in this CA's CRL.
func (oneCa *OneCaType) certificateIsRevocable(issuedCertificate *x509.Certificate) error {
	if issuedCertificate.Equal(oneCa.caCertificate) {
		return fmt.Errorf(
			"%w: serial %s is the CA certificate itself",
			ErrCannotRevokeCaCertificate,
			issuedCertificate.SerialNumber.String(),
		)
	}
	if err := validateCertificateAgainstCa(issuedCertificate, oneCa.caCertificate); err != nil {
		return fmt.Errorf("%w: %w", ErrCertificateNotIssuedByThisCa, err)
	}
	return nil
}

func writeIssuedCertificate(
	ctx context.Context,
	logger types.Logger,
	issuedCertificatesDir string,
	issuedCertificate *x509.Certificate,
	pemBytes []byte,
) error {
	certificateFilename := filepath.Join(issuedCertificatesDir, issuedCertificate.SerialNumber.String()+".crt.pem")

	logger.DebugContext(ctx, "writing issued certificate", "filename", certificateFilename)
	return writeCertificateFileExclusive(certificateFilename, pemBytes)
}

func writeCertificateFileExclusive(filename string, pemBytes []byte) error {
	return atomicWriteFileExclusive(filename, pemBytes, os.FileMode(0o644))
}
