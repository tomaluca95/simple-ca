package caissuingprocess_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

// readCaCertificate returns the CA certificate the way the data directory holds
// it, so a test can compare what was signed against what was configured.
func readCaCertificate(t *testing.T, dataDirectory string, caId string) *x509.Certificate {
	t.Helper()
	certificatePemBytes, err := os.ReadFile(filepath.Join(dataDirectory, caId, "data", "crt", "1.crt.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certificatePemBlock, _ := pem.Decode(certificatePemBytes)
	if certificatePemBlock == nil {
		t.Fatal("no pem block in the CA certificate")
	}
	certificate, err := x509.ParseCertificate(certificatePemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// The CA certificate carries the instant the configuration declared, to the
// second, and not a window measured from whenever the tool happened to run.
func TestCaCertificateCarriesTheDeclaredExpiry(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{
		NotAfter: time.Date(2031, time.June, 15, 8, 30, 0, 0, time.UTC),
	}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Fatal(err)
	}

	certificate := readCaCertificate(t, dataDirectory, caId)
	if !certificate.NotAfter.Equal(configData.Validity.NotAfter) {
		t.Errorf(
			"the certificate expires at %s, want the declared %s",
			certificate.NotAfter.UTC().Format(time.RFC3339),
			configData.Validity.NotAfter.UTC().Format(time.RFC3339),
		)
	}
}

// A declared expiry finer than a second is trimmed to what a certificate can
// store, and the load check compares it against the trimmed value: without that,
// a config with sub-second precision would create a CA it then refused.
func TestCaCertificateExpiryIsTrimmedToWholeSeconds(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{
		NotAfter: time.Date(2031, time.June, 15, 8, 30, 0, 500000000, time.UTC),
	}
	oneCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oneCa.GetIssuerPem(); err != nil {
		t.Fatal(err)
	}

	certificate := readCaCertificate(t, dataDirectory, caId)
	if !certificate.NotAfter.Equal(configData.Validity.NotAfter.Truncate(time.Second)) {
		t.Errorf(
			"the certificate expires at %s, want the declared instant trimmed to the second",
			certificate.NotAfter.UTC().Format(time.RFC3339Nano),
		)
	}

	// And the same config loads again, which is the check that would have
	// compared the untrimmed value.
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Errorf("a config whose expiry is finer than a second must load its own CA, got %v", err)
	}
}

// The load check compares the declared instant with the one in the certificate,
// so it holds on any day the tool runs. This is the case that used to fail: a
// CA declared with months: 1, created on the 30th of a month, was refused on the
// 1st of the next one because "one month from now" had become a different
// length. Nothing about the check is a function of the load time now, and the
// only way to show that from inside one process is to declare an expiry that is
// entirely unrelated to the calendar -- no relative amount, no month, no clock.
func TestCaCertificateLoadsWhateverTheDateIs(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	// A month-shaped window, declared as the two instants it actually is. The
	// old check compared the length of this window against
	// now.AddDate(0, 1, 0) - now, which is 30 days in some months and 31 in
	// others; the new one compares these two values and nothing else.
	createdOn := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{NotAfter: createdOn.AddDate(0, 1, 0)}
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Fatal(err)
	}

	// Whatever "now" is when this runs, and whatever month it falls in, the
	// declared expiry is still what the certificate carries and the check still
	// holds.
	for range 3 {
		if _, err := caissuingprocess.LoadOneCa(
			context.Background(),
			&types.StdLogger{},
			caId,
			dataDirectory,
			configData,
		); err != nil {
			t.Fatalf("a CA with a declared expiry must load on any date, got %v", err)
		}
	}
}

// clock_skew only ever reached the CA's own certificate as a distance, and the
// load check compared that distance, so changing the skew after the fact made
// the next load report the CA certificate as changed -- a certificate whose
// notBefore had been fixed at signing and cannot be otherwise. With the check
// reading the declared expiry and nothing else, the skew is free to change: it
// applies from then on to what the CA issues, and the root is left alone.
func TestCaCertificateSkewCanChangeAfterCreation(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	configData.ClockSkew = time.Hour
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Fatal(err)
	}
	notBeforeWhenSigned := readCaCertificate(t, dataDirectory, caId).NotBefore

	configData.ClockSkew = 5 * time.Minute
	if _, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	); err != nil {
		t.Fatalf("changing clock_skew after creation must not stop the CA from loading, got %v", err)
	}
	if notBefore := readCaCertificate(t, dataDirectory, caId).NotBefore; !notBefore.Equal(notBeforeWhenSigned) {
		t.Errorf(
			"the CA certificate's notBefore moved from %s to %s",
			notBeforeWhenSigned.UTC().Format(time.RFC3339),
			notBefore.UTC().Format(time.RFC3339),
		)
	}
}

// A CA is never signed into existence already expired. The date in a config is
// written once, and a config left behind for a year would otherwise produce a
// root that no verifier accepts and no client can pin.
func TestCreatingACaWithAnExpiryInThePastFails(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{
		NotAfter: time.Now().Add(-time.Hour),
	}
	_, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	)
	if !errors.Is(err, caissuingprocess.ErrCaCertificateAlreadyExpired) {
		t.Fatalf("expected ErrCaCertificateAlreadyExpired, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dataDirectory, caId, "data", "crt", "1.crt.pem")); !os.IsNotExist(statErr) {
		t.Error("no CA certificate must be left behind")
	}
}

// An expiry in the future by a hair is enough: the check is against the clock at
// the moment of signing, not rounded to a unit.
func TestCreatingACaExpiringWithinTheSecondIsRefused(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{
		NotAfter: time.Now().Add(100 * time.Millisecond),
	}
	_, err := caissuingprocess.LoadOneCa(
		context.Background(),
		&types.StdLogger{},
		caId,
		dataDirectory,
		configData,
	)
	if !errors.Is(err, caissuingprocess.ErrCaCertificateAlreadyExpired) {
		t.Fatalf("expected ErrCaCertificateAlreadyExpired, got %v", err)
	}
}

// An existing CA whose expiry has passed still loads, so that what is left of
// its issuance stays revocable. A tool that refuses to start on an expired root
// cannot revoke anything, and the certificates it signed are the ones that most
// need revoking.
//
// Built by signing a certificate that is already expired, which is what a CA
// looks like the day after its expiry: the tool will not sign one, so the
// certificate is written the way the load path would have found it.
func TestACaThatHasExpiredStillLoads(t *testing.T) {
	dataDirectory := t.TempDir()
	caId := "test_ca_1"
	logger := &types.StdLogger{}

	// A CA created the normal way, to get a key and a data directory laid out
	// the way the load path expects.
	notAfter := time.Now().Add(24 * time.Hour)
	configData := newRsaTestCaConfig()
	configData.Validity = types.CertificateAuthorityValidityType{NotAfter: notAfter}
	oneCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuerPem, err := oneCa.GetIssuerPem()
	if err != nil {
		t.Fatal(err)
	}
	issuerPemBlock, _ := pem.Decode(issuerPem)
	if issuerPemBlock == nil {
		t.Fatal("no pem block in the issuer certificate")
	}
	issuer, err := x509.ParseCertificate(issuerPemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPemBytes, err := os.ReadFile(filepath.Join(dataDirectory, caId, "ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPemBlock, _ := pem.Decode(privateKeyPemBytes)
	if privateKeyPemBlock == nil {
		t.Fatal("no pem block in the CA key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// The same certificate with an expiry a year behind us. Every field the load
	// check compares is carried over from the one the tool signed, including the
	// name constraints, so the only thing that differs afterwards is the expiry.
	expiredNotAfter := time.Now().Add(-365 * 24 * time.Hour)
	expiredTemplate := &x509.Certificate{
		SerialNumber:                issuer.SerialNumber,
		Subject:                     issuer.Subject,
		NotBefore:                   issuer.NotBefore,
		NotAfter:                    expiredNotAfter,
		BasicConstraintsValid:       issuer.BasicConstraintsValid,
		IsCA:                        issuer.IsCA,
		KeyUsage:                    issuer.KeyUsage,
		ExtKeyUsage:                 issuer.ExtKeyUsage,
		PermittedDNSDomains:         issuer.PermittedDNSDomains,
		ExcludedDNSDomains:          issuer.ExcludedDNSDomains,
		PermittedDNSDomainsCritical: issuer.PermittedDNSDomainsCritical,
		PermittedIPRanges:           issuer.PermittedIPRanges,
		ExcludedIPRanges:            issuer.ExcludedIPRanges,
		PermittedEmailAddresses:     issuer.PermittedEmailAddresses,
		ExcludedEmailAddresses:      issuer.ExcludedEmailAddresses,
		PermittedURIDomains:         issuer.PermittedURIDomains,
		ExcludedURIDomains:          issuer.ExcludedURIDomains,
	}
	expiredDer, err := x509.CreateCertificate(rand.Reader, expiredTemplate, issuer, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dataDirectory, caId, "data", "crt", "1.crt.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDer}),
		os.FileMode(0o644),
	); err != nil {
		t.Fatal(err)
	}
	expiredConfigData := newRsaTestCaConfig()
	expiredConfigData.Validity = types.CertificateAuthorityValidityType{NotAfter: expiredNotAfter}

	expiredCa, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		expiredConfigData,
	)
	if err != nil {
		t.Fatalf("an expired CA must still load, so that its issuance can be revoked, got %v", err)
	}

	// And it still serves a CRL: the endpoint a relying party asks is the one
	// that has to keep answering.
	if _, err := expiredCa.GetCrlPem(); err != nil {
		t.Errorf("an expired CA must still publish its CRL, got %v", err)
	}
}
