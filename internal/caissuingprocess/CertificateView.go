package caissuingprocess

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net"
	"net/url"
	"time"
)

type CertificateView struct {
	Subject               CertificateViewSubject     `json:"subject"`
	SerialNumber          string                     `json:"serial_number"`
	NotBefore             string                     `json:"not_before"`
	NotAfter              string                     `json:"not_after"`
	IsCA                  bool                       `json:"is_ca"`
	BasicConstraintsValid bool                       `json:"basic_constraints_valid"`
	MaxPathLen            *int                       `json:"max_path_len,omitempty"`
	KeyUsage              []string                   `json:"key_usage"`
	ExtendedKeyUsage      []string                   `json:"extended_key_usage"`
	DNSNames              []string                   `json:"dns_names"`
	EmailAddresses        []string                   `json:"email_addresses"`
	IPAddresses           []string                   `json:"ip_addresses"`
	URIs                  []string                   `json:"uris"`
	PublicKey             CertificateViewPublicKey   `json:"public_key"`
	SignatureAlgorithm    string                     `json:"signature_algorithm"`
	Extensions            []CertificateViewExtension `json:"extensions"`
}

type CertificateViewSubject struct {
	CommonName         string   `json:"common_name"`
	Country            []string `json:"country"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Locality           []string `json:"locality"`
	Province           []string `json:"province"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
}

type CertificateViewPublicKey struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
}

type CertificateViewExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	ValueHex string `json:"value_hex"`
}

func NewCertificateView(cert *x509.Certificate) CertificateView {
	serialNumber := ""
	if cert.SerialNumber != nil {
		serialNumber = cert.SerialNumber.String()
	}
	var maxPathLen *int
	if cert.MaxPathLenZero || cert.MaxPathLen > 0 {
		value := cert.MaxPathLen
		maxPathLen = &value
	}
	return CertificateView{
		Subject: CertificateViewSubject{
			CommonName:         cert.Subject.CommonName,
			Country:            nonNilStrings(cert.Subject.Country),
			Organization:       nonNilStrings(cert.Subject.Organization),
			OrganizationalUnit: nonNilStrings(cert.Subject.OrganizationalUnit),
			Locality:           nonNilStrings(cert.Subject.Locality),
			Province:           nonNilStrings(cert.Subject.Province),
			StreetAddress:      nonNilStrings(cert.Subject.StreetAddress),
			PostalCode:         nonNilStrings(cert.Subject.PostalCode),
		},
		SerialNumber:          serialNumber,
		NotBefore:             cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:              cert.NotAfter.UTC().Format(time.RFC3339),
		IsCA:                  cert.IsCA,
		BasicConstraintsValid: cert.BasicConstraintsValid,
		MaxPathLen:            maxPathLen,
		KeyUsage:              keyUsageNames(cert.KeyUsage),
		ExtendedKeyUsage:      extKeyUsageNames(cert.ExtKeyUsage),
		DNSNames:              nonNilStrings(cert.DNSNames),
		EmailAddresses:        nonNilStrings(cert.EmailAddresses),
		IPAddresses:           ipAddressStrings(cert.IPAddresses),
		URIs:                  uriStrings(cert.URIs),
		PublicKey:             publicKeyView(cert.PublicKey),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		Extensions:            extensionViews(cert.Extensions),
	}
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func ipAddressStrings(in []net.IP) []string {
	out := make([]string, 0, len(in))
	for _, ip := range in {
		out = append(out, ip.String())
	}
	return out
}

func uriStrings(in []*url.URL) []string {
	out := make([]string, 0, len(in))
	for _, uri := range in {
		if uri != nil {
			out = append(out, uri.String())
		}
	}
	return out
}

func publicKeyView(publicKey any) CertificateViewPublicKey {
	switch typed := publicKey.(type) {
	case *rsa.PublicKey:
		return CertificateViewPublicKey{Algorithm: "RSA", Bits: typed.N.BitLen()}
	case *ecdsa.PublicKey:
		bits := 0
		if typed.Curve != nil {
			bits = typed.Curve.Params().BitSize
		}
		return CertificateViewPublicKey{Algorithm: "ECDSA", Bits: bits}
	case ed25519.PublicKey:
		return CertificateViewPublicKey{Algorithm: "Ed25519", Bits: len(typed) * 8}
	default:
		return CertificateViewPublicKey{Algorithm: "unknown", Bits: 0}
	}
}

var keyUsageNameByBit = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "certSign"},
	{x509.KeyUsageCRLSign, "crlSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsageNames(keyUsage x509.KeyUsage) []string {
	out := []string{}
	for _, entry := range keyUsageNameByBit {
		if keyUsage&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

func extKeyUsageNames(extKeyUsage []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(extKeyUsage))
	for _, usage := range extKeyUsage {
		out = append(out, usage.String())
	}
	return out
}

func extensionViews(extensions []pkix.Extension) []CertificateViewExtension {
	out := make([]CertificateViewExtension, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, CertificateViewExtension{
			OID:      extension.Id.String(),
			Critical: extension.Critical,
			ValueHex: hex.EncodeToString(extension.Value),
		})
	}
	return out
}
