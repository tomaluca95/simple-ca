package caissuingprocess

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// provisionalCertificateForAuthorization builds an unsigned certificate that
// mirrors what CreateCertificate will emit for policy inspection: subject,
// SANs, serial, validity, public key, and CSR extensions. BasicConstraints
// from ExtraExtensions are applied so IsCA routing matches the signed result.
// Authorization runs on this value before the CA private key is used.
//
// A basicConstraints extension that cannot be cleanly parsed is refused: Go's
// CreateCertificate may still treat the same bytes as CA:TRUE, and silent
// IsCA=false here would route pre-authorization to the leaf policy.
func provisionalCertificateForAuthorization(template *x509.Certificate, publicKey any) (*x509.Certificate, error) {
	provisional := *template
	provisional.PublicKey = publicKey
	provisional.ExtraExtensions = append([]pkix.Extension(nil), template.ExtraExtensions...)
	provisional.Extensions = append([]pkix.Extension(nil), template.ExtraExtensions...)
	if err := applyBasicConstraintsFromExtensions(&provisional); err != nil {
		return nil, err
	}
	return &provisional, nil
}

func applyBasicConstraintsFromExtensions(cert *x509.Certificate) error {
	extension, ok := basicConstraintsExtension(cert.Extensions)
	if !ok {
		return nil
	}
	var basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	rest, err := asn1.Unmarshal(extension.Value, &basicConstraints)
	if err != nil {
		return fmt.Errorf("%w: malformed basicConstraints: %v", ErrInvalidCsr, err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("%w: malformed basicConstraints: trailing ASN.1 bytes", ErrInvalidCsr)
	}
	cert.BasicConstraintsValid = true
	cert.IsCA = basicConstraints.IsCA
	if basicConstraints.MaxPathLen >= 0 {
		cert.MaxPathLen = basicConstraints.MaxPathLen
		cert.MaxPathLenZero = basicConstraints.MaxPathLen == 0
	}
	return nil
}

func basicConstraintsExtension(extensions []pkix.Extension) (pkix.Extension, bool) {
	for i := 0; i < len(extensions); i++ {
		if extensions[i].Id.Equal(oidExtensionBasicConstraints) {
			return extensions[i], true
		}
	}
	return pkix.Extension{}, false
}
