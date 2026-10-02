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

	now := time.Now()
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
		// notBefore is backdated by the configured skew so a verifier whose
		// clock lags accepts a freshly issued certificate. It is fixed when the
		// certificate is signed, and the load check does not look at it: the
		// expiry is declared, not derived, so nothing here depends on when the
		// load happens.
		NotBefore: now.Add(-caConfig.ClockSkew),
		// Trimmed to whole seconds because that is what a certificate carries:
		// a configuration naming a finer instant would create a certificate
		// that the load check then refused as different from the config.
		NotAfter: caConfig.Validity.NotAfter.UTC().Truncate(time.Second),

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
