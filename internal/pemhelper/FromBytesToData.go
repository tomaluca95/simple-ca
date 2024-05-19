package pemhelper

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func extractBytesFromPem(rawPemData []byte, pemType string) ([]byte, error) {
	pemBlock, rest := pem.Decode(rawPemData)
	if restLen := len(rest); restLen != 0 {
		return nil, fmt.Errorf("%w: %d", ErrPemInvalidReminder, restLen)
	}

	if pemBlock == nil {
		return nil, ErrPemEmpty
	}

	if pemBlock.Type != pemType {
		return nil, fmt.Errorf("%w: %s expected %s", ErrPemInvalidTypeFound, pemBlock.Type, pemType)
	}

	return pemBlock.Bytes, nil
}

func FromPemToEcdsaPrivateKey(rawPemData []byte) (*ecdsa.PrivateKey, error) {
	pemBlockBytes, err := extractBytesFromPem(rawPemData, "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(pemBlockBytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func FromPemToRsaPrivateKey(rawPemData []byte) (*rsa.PrivateKey, error) {
	pemBlockBytes, err := extractBytesFromPem(rawPemData, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(pemBlockBytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func FromPemToCertificate(rawPemData []byte) (*x509.Certificate, error) {
	pemBlockBytes, err := extractBytesFromPem(rawPemData, "CERTIFICATE")
	if err != nil {
		return nil, err
	}

	certData, err := x509.ParseCertificate(pemBlockBytes)
	if err != nil {
		return nil, err
	}
	return certData, nil
}

func FromPemToCertificateRequest(rawPemData []byte) (*x509.CertificateRequest, error) {
	pemBlockBytes, err := extractBytesFromPem(rawPemData, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}

	certData, err := x509.ParseCertificateRequest(pemBlockBytes)
	if err != nil {
		return nil, err
	}
	return certData, nil
}
