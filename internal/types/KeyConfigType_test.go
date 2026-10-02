package types_test

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func decodeConfig(t *testing.T, yamlText string) types.CertificateAuthorityType {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(yamlText))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	if err := decoder.Decode(&config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestKeyConfigRsa(t *testing.T) {
	config := decodeConfig(t, `
key_config:
    type: rsa
    config:
        size: 4096
`)
	keyConfig, ok := config.KeyConfig.Config.(types.KeyTypeRsaConfigType)
	if !ok {
		t.Fatalf("unexpected config type %T", config.KeyConfig.Config)
	}
	if keyConfig.Size != 4096 {
		t.Fatalf("invalid size %d", keyConfig.Size)
	}
}

func TestKeyConfigEcdsa(t *testing.T) {
	config := decodeConfig(t, `
key_config:
    type: ecdsa
    config:
        curve_name: P-256
`)
	keyConfig, ok := config.KeyConfig.Config.(types.KeyTypeEcdsaConfigType)
	if !ok {
		t.Fatalf("unexpected config type %T", config.KeyConfig.Config)
	}
	if keyConfig.CurveName != "P-256" {
		t.Fatalf("invalid curve %q", keyConfig.CurveName)
	}
}

func TestKeyConfigRsaUnknownField(t *testing.T) {
	decoder := yaml.NewDecoder(strings.NewReader(`
key_config:
    type: rsa
    config:
        size: 4096
        bogus: 1
`))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	if err := decoder.Decode(&config); err == nil {
		t.Error("expected error for unknown field in rsa config")
	}
}

func TestKeyConfigEcdsaUnknownField(t *testing.T) {
	decoder := yaml.NewDecoder(strings.NewReader(`
key_config:
    type: ecdsa
    config:
        curve_name: P-256
        bogus: 1
`))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	if err := decoder.Decode(&config); err == nil {
		t.Error("expected error for unknown field in ecdsa config")
	}
}

func TestKeyConfigUnknownField(t *testing.T) {
	decoder := yaml.NewDecoder(strings.NewReader(`
key_config:
    type: rsa
    config:
        size: 4096
    bogus: 1
`))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	if err := decoder.Decode(&config); err == nil {
		t.Error("expected error for unknown field in key_config")
	}
}

func TestKeyConfigInvalidType(t *testing.T) {
	decoder := yaml.NewDecoder(strings.NewReader(`
key_config:
    type: dsa
    config: {}
`))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	err := decoder.Decode(&config)
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
	if !errors.Is(err, types.ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got %v", err)
	}
}
