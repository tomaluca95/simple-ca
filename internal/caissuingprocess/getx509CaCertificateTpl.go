package caissuingprocess

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func getx509CaCertificateTpl(caConfig types.CertificateAuthorityType) (*x509.Certificate, error) {
	permittedIPRanges := []*net.IPNet{}
	for _, n := range caConfig.PermittedIPRanges {
		_, parsed, err := net.ParseCIDR(n)
		if err != nil {
			return nil, err
		}
		permittedIPRanges = append(permittedIPRanges, parsed)
	}

	excludedIPRanges := []*net.IPNet{}
	for _, n := range caConfig.ExcludedIPRanges {
		_, parsed, err := net.ParseCIDR(n)
		if err != nil {
			return nil, err
		}
		excludedIPRanges = append(excludedIPRanges, parsed)
	}

	tpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         caConfig.Subject.CommonName,
			Country:            caConfig.Subject.Country,
			Organization:       caConfig.Subject.Organization,
			OrganizationalUnit: caConfig.Subject.OrganizationalUnit,
			Locality:           caConfig.Subject.Locality,
			Province:           caConfig.Subject.Province,
			StreetAddress:      caConfig.Subject.StreetAddress,
			PostalCode:         caConfig.Subject.PostalCode,
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter: time.Now().AddDate(
			caConfig.Validity.Years,
			caConfig.Validity.Months,
			caConfig.Validity.Days,
		),

		BasicConstraintsValid:       true,
		PermittedDNSDomainsCritical: caConfig.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         caConfig.PermittedDNSDomains,
		ExcludedDNSDomains:          caConfig.ExcludedDNSDomains,
		PermittedIPRanges:           permittedIPRanges,
		ExcludedIPRanges:            excludedIPRanges,
		PermittedEmailAddresses:     caConfig.PermittedEmailAddresses,
		ExcludedEmailAddresses:      caConfig.ExcludedEmailAddresses,
		PermittedURIDomains:         caConfig.PermittedURIDomains,
		ExcludedURIDomains:          caConfig.ExcludedURIDomains,

		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return tpl, nil
}
