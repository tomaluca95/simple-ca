package caissuingprocess

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// caPrivateKeyMatchesCertificate fails when the private key cannot have signed
// the CA certificate. A CA whose key does not match the certificate it
// publishes is broken in a way nothing else reports: it still starts, it still
// answers /issuer.pem, but every certificate it signs chains to nothing and
// every CRL it signs fails verification, so the mismatch has to stop the load
// instead.
func caPrivateKeyMatchesCertificate(
	caPrivateKey crypto.Signer,
	caCertificate *x509.Certificate,
	caFilenamePrivateKey string,
	caCertificateFilename string,
) error {
	keyPublicKeyDer, err := x509.MarshalPKIXPublicKey(caPrivateKey.Public())
	if err != nil {
		return fmt.Errorf(
			"%w: unable to read the public key of %s: %v",
			ErrCaKeyMismatch,
			caFilenamePrivateKey,
			err,
		)
	}
	certificatePublicKeyDer, err := x509.MarshalPKIXPublicKey(caCertificate.PublicKey)
	if err != nil {
		return fmt.Errorf(
			"%w: unable to read the public key of %s: %v",
			ErrCaKeyMismatch,
			caCertificateFilename,
			err,
		)
	}
	if bytes.Equal(keyPublicKeyDer, certificatePublicKeyDer) {
		return nil
	}
	return fmt.Errorf(
		"%w: %s holds the public key %s while %s holds %s, so this key cannot sign for the certificate clients already trust: restore the private key that created the certificate, or delete both files to bootstrap a new CA",
		ErrCaKeyMismatch,
		caFilenamePrivateKey,
		publicKeyFingerprint(keyPublicKeyDer),
		caCertificateFilename,
		publicKeyFingerprint(certificatePublicKeyDer),
	)
}

// publicKeyFingerprint is a short, stable identifier of a public key, so an
// operator can tell two keys apart without dumping both of them.
func publicKeyFingerprint(publicKeyDer []byte) string {
	fingerprint := sha256.Sum256(publicKeyDer)
	return "sha256:" + hex.EncodeToString(fingerprint[:6])
}

// caKeyPresentForCertificate refuses to bootstrap a private key when the CA
// certificate it is supposed to belong to is already there. Only the pair being
// absent together is a bootstrap; the certificate alone is a CA whose key was
// lost, and creating a key for it would destroy the last chance of recovering
// the original one.
func caKeyPresentForCertificate(
	caFilenamePrivateKey string,
	caCertificateFilename string,
) error {
	_, certificateErr := os.Stat(caCertificateFilename)
	switch {
	case certificateErr == nil:
		_, keyErr := os.Stat(caFilenamePrivateKey)
		if keyErr == nil {
			return nil
		}
		if !errors.Is(keyErr, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", caFilenamePrivateKey, keyErr)
		}
		return fmt.Errorf(
			"%w: %s exists but the private key %s is missing: restore the key that created the certificate, or delete both files to bootstrap a new CA",
			ErrCaKeyMismatch,
			caCertificateFilename,
			caFilenamePrivateKey,
		)
	case errors.Is(certificateErr, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("%s: %w", caCertificateFilename, certificateErr)
	}
}
