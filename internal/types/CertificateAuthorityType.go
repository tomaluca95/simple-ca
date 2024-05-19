package types

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type CertificateAuthorityType struct {
	Subject   CertificateAuthoritySubjectType
	Validity  CertificateAuthorityValidityType
	KeyConfig KeyConfigType `yaml:"key_config"`
	CrlTtl    time.Duration `yaml:"crl_ttl"`

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

type KeyConfigType struct {
	Type   string `yaml:"type"`
	Config any    `yaml:"config"`
}

var ErrInvalidKeyType = fmt.Errorf("invalid key type")

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
	switch e.Type {
	case "rsa":
		var keyConfig KeyTypeRsaConfigType
		if err := yaml.Unmarshal(configYamlBytes, &keyConfig); err != nil {
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
