package caissuingprocess

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"time"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
)

var ErrInvalidKeyTypeInCsr = fmt.Errorf("invalid key type for csr")

func signOneCsr(
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
		return nil, err
	}

	log.Println("Loading CSR: " + csr.Subject.String())

	serialNumber := new(big.Int).Add(
		big.NewInt(rand.Int63()),
		new(big.Int).Mul(
			big.NewInt(time.Now().UnixMilli()),
			new(big.Int).Add(
				big.NewInt(1),
				big.NewInt(math.MaxInt64),
			),
		),
	)

	publicKey, keyOk := csr.PublicKey.(*rsa.PublicKey)
	if !keyOk {
		return nil, fmt.Errorf("%w: %T", ErrInvalidKeyTypeInCsr, csr.PublicKey)
	}
	crtTemplate := &x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),

		Version:         csr.Version,
		Extensions:      append(csr.Extensions, csr.ExtraExtensions...),
		ExtraExtensions: append(csr.Extensions, csr.ExtraExtensions...),
		DNSNames:        csr.DNSNames,
		EmailAddresses:  csr.EmailAddresses,
		IPAddresses:     csr.IPAddresses,
		URIs:            csr.URIs,
	}

	pemBlock, err := certificateCreateNew(
		issuedCertificatesDir,
		crtTemplate,
		caCertificate,
		publicKey,
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
