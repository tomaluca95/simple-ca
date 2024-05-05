package types

import "time"

type CertificateAuthorityType struct {
	Subject  CertificateAuthoritySubjectType
	Validity CertificateAuthorityValidityType
	KeySize  int           `yaml:"key_size"`
	CrlTtl   time.Duration `yaml:"crl_ttl"`

	HttpServerOptions *HttpServerOptionsType `yaml:"http_server_options"`

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
