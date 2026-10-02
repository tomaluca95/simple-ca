package types

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxClockSkew is the largest backdating window a CA may configure. Larger
// values push notBefore (and CRL thisUpdate) far into the past for every
// issuance, which weakens freshness checks without helping lagging verifiers.
const MaxClockSkew = time.Hour

// MinCrlTtl is the smallest crl_ttl a CA may configure. The published CRL is
// rewritten every crl_ttl/4, and each rewrite is a full revocation list: it
// signs, fsyncs, and commits to the CA's own git history. A crl_ttl below a
// few minutes therefore does not buy a fresher list, it buys a server that
// signs and commits as fast as the CPU allows while nobody is asking for
// anything -- measured at 67% of one core for a crl_ttl of 4ms, on an
// otherwise idle CA. Ten minutes keeps the refresh every 2m30s, which is
// finer than any client that polls a CRL, and refuses the values that can
// only be a mistake.
const MinCrlTtl = 10 * time.Minute

type CertificateAuthorityType struct {
	Subject   CertificateAuthoritySubjectType
	Validity  CertificateAuthorityValidityType
	KeyConfig KeyConfigType `yaml:"key_config"`
	CrlTtl    time.Duration `yaml:"crl_ttl"`
	ClockSkew time.Duration `yaml:"clock_skew"`

	OpaUrlSign    *string `yaml:"opa_url_sign"`
	OpaUrlRevoke  *string `yaml:"opa_url_revoke"`
	OpaUrlIssueCa *string `yaml:"opa_url_issue_ca"`

	// Each OPA endpoint has its own per-call budget. Zero means the default
	// (500ms), enforced by internal/opa.
	OpaTimeoutSign    time.Duration `yaml:"opa_timeout_sign"`
	OpaTimeoutRevoke  time.Duration `yaml:"opa_timeout_revoke"`
	OpaTimeoutIssueCa time.Duration `yaml:"opa_timeout_issue_ca"`

	PermittedDNSDomainsCritical bool     `yaml:"permitted_dns_domains_critical"`
	PermittedDNSDomains         []string `yaml:"permitted_dns_domains"`
	ExcludedDNSDomains          []string `yaml:"excluded_dns_domains"`
	PermittedIPRanges           []string `yaml:"permitted_ip_ranges"`
	ExcludedIPRanges            []string `yaml:"excluded_ip_ranges"`
	PermittedEmailAddresses     []string `yaml:"permitted_email_addresses"`
	ExcludedEmailAddresses      []string `yaml:"excluded_email_addresses"`
	PermittedURIDomains         []string `yaml:"permitted_uri_domains"`
	ExcludedURIDomains          []string `yaml:"excluded_uri_domains"`
}

type KeyConfigType struct {
	Type   string `yaml:"type"`
	Config any    `yaml:"config"`
}

func (e *KeyConfigType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var internalNode struct {
		Type   string    `yaml:"type"`
		Config yaml.Node `yaml:"config"`
	}

	if err := unmarshal(&internalNode); err != nil {
		return err
	}

	e.Type = internalNode.Type

	configYamlBytes, err := yaml.Marshal(internalNode.Config)
	if err != nil {
		return err
	}
	configDecoder := yaml.NewDecoder(bytes.NewReader(configYamlBytes))
	configDecoder.KnownFields(true)

	switch e.Type {
	case "rsa":
		var keyConfig KeyTypeRsaConfigType
		if err := configDecoder.Decode(&keyConfig); err != nil {
			return err
		}
		e.Config = keyConfig

		return nil
	case "ecdsa":
		var keyConfig KeyTypeEcdsaConfigType
		if err := configDecoder.Decode(&keyConfig); err != nil {
			return err
		}
		e.Config = keyConfig

		return nil

	default:
		return fmt.Errorf("%w: %s", ErrInvalidKeyType, e.Type)
	}

}

type KeyTypeRsaConfigType struct {
	Size int `yaml:"size"`
}

type KeyTypeEcdsaConfigType struct {
	CurveName string `yaml:"curve_name"`
}

// Validate returns one problem per invalid field, so the caller can report the
// whole configuration at once.
func (caConfig CertificateAuthorityType) Validate() []error {
	problems := []error{}

	if strings.TrimSpace(caConfig.Subject.CommonName) == "" {
		problems = append(problems, fmt.Errorf("%w: subject.common_name must not be empty", ErrInvalidConfig))
	}

	switch keyConfigData := caConfig.KeyConfig.Config.(type) {
	case KeyTypeRsaConfigType:
		if keyConfigData.Size < MinRsaPublicKeyBits {
			problems = append(problems, fmt.Errorf("%w: key_config.config.size %d is below the minimum of %d", ErrInvalidConfig, keyConfigData.Size, MinRsaPublicKeyBits))
		}
	case KeyTypeEcdsaConfigType:
		// The same list the key itself is measured against, so a config cannot
		// name a curve the CA would then refuse to load.
		if !EllipticCurveIsApproved(keyConfigData.CurveName) {
			problems = append(problems, fmt.Errorf(
				"%w: %w: key_config.config.curve_name %q is not one of %s",
				ErrInvalidConfig, ErrInvalidCurve, keyConfigData.CurveName,
				strings.Join(ApprovedEllipticCurves(), ", "),
			))
		}
	default:
		problems = append(problems, fmt.Errorf(
			"%w: %w: key_config.type %q is not one of rsa, ecdsa",
			ErrInvalidConfig, ErrInvalidKeyType, caConfig.KeyConfig.Type,
		))
	}

	if caConfig.CrlTtl < MinCrlTtl {
		problems = append(problems, fmt.Errorf(
			"%w: crl_ttl %s must be at least %s",
			ErrInvalidConfig, caConfig.CrlTtl, MinCrlTtl,
		))
	}

	if caConfig.ClockSkew < 0 {
		problems = append(problems, fmt.Errorf("%w: clock_skew must not be negative", ErrInvalidConfig))
	}
	if caConfig.ClockSkew > MaxClockSkew {
		problems = append(problems, fmt.Errorf("%w: clock_skew must not exceed %s", ErrInvalidConfig, MaxClockSkew))
	}

	if caConfig.PermittedDNSDomainsCritical && len(caConfig.PermittedDNSDomains) == 0 {
		problems = append(problems, fmt.Errorf(
			"%w: permitted_dns_domains_critical is true but permitted_dns_domains is empty",
			ErrInvalidConfig,
		))
	}

	// The CA's expiry is a declared instant, so there is nothing to resolve and
	// nothing to compare against the clock here. Only a CA that does not exist
	// yet needs it to be in the future, and that is checked where the
	// certificate is created: an expired CA must still load, so that what is
	// left of its issuance can be revoked.
	if caConfig.Validity.NotAfter.IsZero() {
		problems = append(problems, fmt.Errorf(
			"%w: validity.not_after must be an ISO 8601 timestamp, for example 2027-10-01T00:00:00Z",
			ErrInvalidConfig,
		))
	}

	for _, opaUrlConfig := range []struct {
		name string
		url  *string
	}{
		{"opa_url_sign", caConfig.OpaUrlSign},
		{"opa_url_revoke", caConfig.OpaUrlRevoke},
		{"opa_url_issue_ca", caConfig.OpaUrlIssueCa},
	} {
		if opaUrlConfig.url == nil || strings.TrimSpace(*opaUrlConfig.url) == "" {
			problems = append(problems, fmt.Errorf("%w: %s must be set", ErrInvalidConfig, opaUrlConfig.name))
			continue
		}
		parsedUrl, err := url.Parse(*opaUrlConfig.url)
		if err != nil || (parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https") || parsedUrl.Host == "" {
			problems = append(problems, fmt.Errorf("%w: %s %q is not a valid http(s) URL", ErrInvalidConfig, opaUrlConfig.name, *opaUrlConfig.url))
		}
	}

	for _, opaTimeoutConfig := range []struct {
		name    string
		timeout time.Duration
	}{
		{"opa_timeout_sign", caConfig.OpaTimeoutSign},
		{"opa_timeout_revoke", caConfig.OpaTimeoutRevoke},
		{"opa_timeout_issue_ca", caConfig.OpaTimeoutIssueCa},
	} {
		if opaTimeoutConfig.timeout < 0 {
			problems = append(problems, fmt.Errorf("%w: %s must not be negative", ErrInvalidConfig, opaTimeoutConfig.name))
		}
	}

	for _, ipRangeConfig := range []struct {
		name   string
		ranges []string
	}{
		{"permitted_ip_ranges", caConfig.PermittedIPRanges},
		{"excluded_ip_ranges", caConfig.ExcludedIPRanges},
	} {
		for _, cidr := range ipRangeConfig.ranges {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				problems = append(problems, fmt.Errorf("%w: %s entry %q is not a valid CIDR", ErrInvalidConfig, ipRangeConfig.name, cidr))
			}
		}
	}

	return problems
}
