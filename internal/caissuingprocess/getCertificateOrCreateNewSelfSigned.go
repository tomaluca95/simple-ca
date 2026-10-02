package caissuingprocess

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

func getCertificateOrCreateNewSelfSigned(
	logger types.Logger,
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
) (*x509.Certificate, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	_, statErr := os.Stat(certificateFilename)
	switch {
	case statErr == nil:
		logger.DebugContext(context.Background(), "CA certificate file exists", "filename", certificateFilename)
	case !os.IsNotExist(statErr):
		return nil, statErr
	default:
		// Only checked when the certificate is about to be created. A CA whose
		// expiry has passed must still load, so that what is left of its
		// issuance can be revoked; what must never happen is a CA born expired,
		// which is a config whose date was written once and then left behind.
		if !templateCertificate.NotAfter.After(time.Now()) {
			return nil, fmt.Errorf(
				"%w: validity.not_after %s, refusing to sign a CA certificate that is already expired",
				ErrCaCertificateAlreadyExpired,
				templateCertificate.NotAfter.UTC().Format(time.RFC3339),
			)
		}
		if _, err := certificateCreateNew(
			logger,
			issuedCertificatesDir,
			templateCertificate,
			caCertificate,
			extractPublicKeyFromSigner(caPrivateKey),
			caPrivateKey,
		); err != nil {
			return nil, err
		}
	}

	logger.DebugContext(context.Background(), "reading CA certificate", "filename", certificateFilename)
	certificateContent, err := os.ReadFile(certificateFilename)
	if err != nil {
		return nil, err
	}
	certificate, err := pemhelper.FromPemToCertificate(certificateContent)
	if err != nil {
		return nil, err
	}

	if differences := certificateTemplateDifferences(templateCertificate, certificate); len(differences) > 0 {
		return nil, fmt.Errorf("%w: %s differs in %s", ErrCaCertificateMismatch, certificateFilename, strings.Join(differences, ", "))
	}
	return certificate, nil
}

func certificateTemplateDifferences(templateCertificate *x509.Certificate, certificate *x509.Certificate) []string {
	differences := []string{}
	if !reflect.DeepEqual(certificate.Subject.ToRDNSequence(), templateCertificate.Subject.ToRDNSequence()) {
		differences = append(differences, "subject")
	}
	// The expiry is the one value a load must not rebuild from the clock. The
	// configuration declares an instant, the certificate carries an instant, and
	// the two are compared as instants. A window measured from the load-time
	// now would be a different length on a different day of the month, which is
	// how a CA created on the 30th of a month stopped loading on the 1st of the
	// next one, refused by the tool that had signed it the day before.
	if !certificate.NotAfter.Equal(templateCertificate.NotAfter) {
		differences = append(differences, describeValidityDifference(certificate, templateCertificate))
	}
	if certificate.IsCA != templateCertificate.IsCA {
		differences = append(differences, "is_ca")
	}
	if certificate.BasicConstraintsValid != templateCertificate.BasicConstraintsValid {
		differences = append(differences, "basic_constraints_valid")
	}
	if certificate.KeyUsage != templateCertificate.KeyUsage {
		differences = append(differences, "key_usage")
	}
	if !reflect.DeepEqual(certificate.ExtKeyUsage, templateCertificate.ExtKeyUsage) {
		differences = append(differences, "extended_key_usage")
	}
	if !reflect.DeepEqual(certificate.PermittedDNSDomains, templateCertificate.PermittedDNSDomains) {
		differences = append(differences, "permitted_dns_domains")
	}
	if !reflect.DeepEqual(certificate.ExcludedDNSDomains, templateCertificate.ExcludedDNSDomains) {
		differences = append(differences, "excluded_dns_domains")
	}
	if !reflect.DeepEqual(certificate.PermittedEmailAddresses, templateCertificate.PermittedEmailAddresses) {
		differences = append(differences, "permitted_email_addresses")
	}
	if !reflect.DeepEqual(certificate.ExcludedEmailAddresses, templateCertificate.ExcludedEmailAddresses) {
		differences = append(differences, "excluded_email_addresses")
	}
	if !reflect.DeepEqual(certificate.PermittedURIDomains, templateCertificate.PermittedURIDomains) {
		differences = append(differences, "permitted_uri_domains")
	}
	if !reflect.DeepEqual(certificate.ExcludedURIDomains, templateCertificate.ExcludedURIDomains) {
		differences = append(differences, "excluded_uri_domains")
	}
	if !ipNetRangesEqual(certificate.PermittedIPRanges, templateCertificate.PermittedIPRanges) {
		differences = append(differences, "permitted_ip_ranges")
	}
	if !ipNetRangesEqual(certificate.ExcludedIPRanges, templateCertificate.ExcludedIPRanges) {
		differences = append(differences, "excluded_ip_ranges")
	}
	if templateCertificateHasNameConstraints(templateCertificate) {
		var nameConstraintsExtension *pkix.Extension
		for i := range certificate.Extensions {
			if certificate.Extensions[i].Id.Equal(oidNameConstraints) {
				nameConstraintsExtension = &certificate.Extensions[i]
				break
			}
		}
		if nameConstraintsExtension == nil ||
			nameConstraintsExtension.Critical != templateCertificate.PermittedDNSDomainsCritical {
			differences = append(differences, "name_constraints_critical")
		}
	}
	return differences
}

// describeValidityDifference names both instants, because the fix for a
// certificate that no longer matches the configuration is to declare the one the
// certificate carries, and that instant is otherwise buried in a file the
// operator has to go and open.
func describeValidityDifference(certificate *x509.Certificate, templateCertificate *x509.Certificate) string {
	return fmt.Sprintf(
		"validity (the certificate expires at %s, the configuration says %s)",
		certificate.NotAfter.UTC().Format(time.RFC3339),
		templateCertificate.NotAfter.UTC().Format(time.RFC3339),
	)
}

func ipNetRangesEqual(a []*net.IPNet, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IP.String() != b[i].IP.String() || a[i].Mask.String() != b[i].Mask.String() {
			return false
		}
	}
	return true
}

func templateCertificateHasNameConstraints(templateCertificate *x509.Certificate) bool {
	return len(templateCertificate.PermittedDNSDomains) > 0 ||
		len(templateCertificate.ExcludedDNSDomains) > 0 ||
		len(templateCertificate.PermittedEmailAddresses) > 0 ||
		len(templateCertificate.ExcludedEmailAddresses) > 0 ||
		len(templateCertificate.PermittedURIDomains) > 0 ||
		len(templateCertificate.ExcludedURIDomains) > 0 ||
		len(templateCertificate.PermittedIPRanges) > 0 ||
		len(templateCertificate.ExcludedIPRanges) > 0
}

func certificateCreateNew(
	logger types.Logger,
	issuedCertificatesDir string,
	templateCertificate *x509.Certificate,
	caCertificate *x509.Certificate,
	newCertificatePublicKey any,
	caPrivateKey crypto.Signer,
) ([]byte, error) {
	certificateFilename := filepath.Join(issuedCertificatesDir, templateCertificate.SerialNumber.String()+".crt.pem")

	logger.DebugContext(context.Background(), "generating new CA certificate", "filename", certificateFilename)
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
	if err := writeCertificateFileExclusive(certificateFilename, pemBytes); err != nil {
		return nil, err
	}
	return pemBytes, nil
}
