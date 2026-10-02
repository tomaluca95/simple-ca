package types_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func validConfigFileData() types.ConfigFileType {
	opaUrl := "http://opa.example/v1/data/simple_ca_sign/allow"
	return types.ConfigFileType{
		DataDirectory: "/tmp/simple-ca-data",
		AllCaConfigs: map[string]types.CertificateAuthorityType{
			"test_ca_1": {
				Subject:       types.CertificateAuthoritySubjectType{CommonName: "test_ca_1"},
				KeyConfig:     types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 2048}},
				CrlTtl:        12 * time.Hour,
				Validity:      testCaValidity,
				OpaUrlSign:    &opaUrl,
				OpaUrlRevoke:  &opaUrl,
				OpaUrlIssueCa: &opaUrl,
			},
		},
	}
}

func TestValidateConfig(t *testing.T) {
	testCases := []struct {
		name             string
		mutate           func(configObject *types.ConfigFileType)
		expectedProblems []string
	}{
		{
			name:   "valid config",
			mutate: func(configObject *types.ConfigFileType) {},
		},
		{
			name:   "valid log level",
			mutate: func(configObject *types.ConfigFileType) { configObject.LogLevel = "debug" },
		},
		{
			name:             "invalid log level",
			mutate:           func(configObject *types.ConfigFileType) { configObject.LogLevel = "verbose" },
			expectedProblems: []string{`log_level "verbose" is not one of debug, info, warn, error`},
		},
		{
			name:             "missing data directory",
			mutate:           func(configObject *types.ConfigFileType) { configObject.DataDirectory = "" },
			expectedProblems: []string{"data_directory must be set"},
		},
		{
			name: "empty common name",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.Subject.CommonName = ""
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"subject.common_name must not be empty"},
		},
		{
			name: "rsa size below the minimum",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.KeyConfig = types.KeyConfigType{Type: "rsa", Config: types.KeyTypeRsaConfigType{Size: 1024}}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"key_config.config.size 1024 is below the minimum of 2048"},
		},
		{
			name: "unknown ecdsa curve",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.KeyConfig = types.KeyConfigType{Type: "ecdsa", Config: types.KeyTypeEcdsaConfigType{CurveName: "P-999"}}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"key_config.config.curve_name"},
		},
		{
			name: "unknown key type",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.KeyConfig = types.KeyConfigType{Type: "dsa", Config: nil}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{`key_config.type "dsa" is not one of rsa, ecdsa`},
		},
		{
			name: "zero crl ttl",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.CrlTtl = 0
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"crl_ttl 0s must be at least 10m0s"},
		},
		{
			// The value that reproduced the burn: refresh every millisecond,
			// signing and committing a CRL nobody is waiting for.
			name: "crl ttl below the minimum",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.CrlTtl = 4 * time.Millisecond
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"crl_ttl 4ms must be at least 10m0s"},
		},
		{
			name: "crl ttl a nanosecond below the minimum",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.CrlTtl = types.MinCrlTtl - time.Nanosecond
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"must be at least 10m0s"},
		},
		{
			name: "negative clock skew",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.ClockSkew = -5 * time.Minute
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"clock_skew must not be negative"},
		},
		{
			name: "clock skew above the maximum",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.ClockSkew = types.MaxClockSkew + time.Second
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"clock_skew must not exceed"},
		},
		{
			name: "critical dns domains with empty list",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.PermittedDNSDomainsCritical = true
				caConfig.PermittedDNSDomains = nil
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"permitted_dns_domains_critical is true but permitted_dns_domains is empty"},
		},
		{
			// Not rejected for being in the past: an expired CA must still load
			// so that what is left of its issuance can be revoked. Only signing
			// a new one refuses a date that has passed.
			name: "expiry already in the past",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.Validity = types.CertificateAuthorityValidityType{NotAfter: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
		},
		{
			name: "no expiry at all",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.Validity = types.CertificateAuthorityValidityType{}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"validity.not_after must be an ISO 8601 timestamp"},
		},
		{
			name: "invalid permitted ip range",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.PermittedIPRanges = []string{"not-a-cidr"}
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{`permitted_ip_ranges entry "not-a-cidr" is not a valid CIDR`},
		},
		{
			name: "missing opa url",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.OpaUrlRevoke = nil
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"opa_url_revoke must be set"},
		},
		{
			name: "opa url that is not a http(s) URL",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				brokenUrl := "notaurl"
				caConfig.OpaUrlSign = &brokenUrl
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{`opa_url_sign "notaurl" is not a valid http(s) URL`},
		},
		{
			name: "reports every problem at once",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.DataDirectory = ""
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.CrlTtl = 0
				caConfig.OpaUrlSign = nil
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"data_directory must be set", "crl_ttl 0s must be at least 10m0s", "opa_url_sign must be set"},
		},
		{
			name: "valid http server timeout",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "127.0.0.1", ListenPort: 5000, Timeout: 30 * time.Second}
			},
		},
		{
			name: "http server timeout not set",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "127.0.0.1", ListenPort: 5000}
			},
		},
		{
			name: "negative http server timeout",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "127.0.0.1", ListenPort: 5000, Timeout: -1 * time.Second}
			},
			expectedProblems: []string{"http_server.timeout must not be negative"},
		},
		{
			name: "http server wildcard ipv4 address",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "0.0.0.0", ListenPort: 5000}
			},
		},
		{
			name: "http server wildcard ipv6 address",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "::", ListenPort: 5000}
			},
		},
		{
			name: "http server ipv6 address",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "::1", ListenPort: 5000}
			},
		},
		{
			name: "missing http server listen address",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenPort: 5000}
			},
			expectedProblems: []string{"http_server.listen_address must be set"},
		},
		{
			name: "http server listen address is not an IP",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "localhost", ListenPort: 5000}
			},
			expectedProblems: []string{`http_server.listen_address "localhost" is not a valid IPv4 or IPv6 address`},
		},
		{
			name: "http server listen port zero",
			mutate: func(configObject *types.ConfigFileType) {
				configObject.HttpServer = &types.HttpServerType{ListenAddress: "127.0.0.1", ListenPort: 0}
			},
			expectedProblems: []string{"http_server.listen_port must not be 0"},
		},
		{
			name: "negative opa timeout",
			mutate: func(configObject *types.ConfigFileType) {
				caConfig := configObject.AllCaConfigs["test_ca_1"]
				caConfig.OpaTimeoutSign = -1 * time.Second
				configObject.AllCaConfigs["test_ca_1"] = caConfig
			},
			expectedProblems: []string{"opa_timeout_sign must not be negative"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configObject := validConfigFileData()
			testCase.mutate(&configObject)

			err := configObject.Validate()
			if len(testCase.expectedProblems) == 0 {
				if err != nil {
					t.Fatalf("expected a valid config, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected problems")
			}
			if !errors.Is(err, types.ErrInvalidConfig) {
				t.Errorf("expected ErrInvalidConfig, got %v", err)
			}
			for _, expectedProblem := range testCase.expectedProblems {
				if !strings.Contains(err.Error(), expectedProblem) {
					t.Errorf("expected the report to contain %q, got %v", expectedProblem, err)
				}
			}
		})
	}
}

func TestValidateConfigAcceptsTheMinimumCrlTtl(t *testing.T) {
	// The floor is a floor, not a value every config is pushed up to: a CA that
	// refreshes its CRL every 2m30s is allowed to say so.
	configObject := validConfigFileData()
	caConfig := configObject.AllCaConfigs["test_ca_1"]
	caConfig.CrlTtl = types.MinCrlTtl
	configObject.AllCaConfigs["test_ca_1"] = caConfig

	if err := configObject.Validate(); err != nil {
		t.Errorf("a crl_ttl of exactly %s must be accepted, got %v", types.MinCrlTtl, err)
	}
}

func TestValidateConfigNamesTheCa(t *testing.T) {
	configObject := validConfigFileData()
	caConfig := configObject.AllCaConfigs["test_ca_1"]
	caConfig.CrlTtl = 0
	configObject.AllCaConfigs["test_ca_1"] = caConfig

	err := configObject.Validate()
	if err == nil {
		t.Fatal("expected problems")
	}
	if !strings.Contains(err.Error(), `CA "test_ca_1"`) {
		t.Errorf("expected the report to name the CA, got %v", err)
	}
}

func TestValidateConfigUnknownCurveIsErrInvalidCurve(t *testing.T) {
	configObject := validConfigFileData()
	caConfig := configObject.AllCaConfigs["test_ca_1"]
	caConfig.KeyConfig = types.KeyConfigType{Type: "ecdsa", Config: types.KeyTypeEcdsaConfigType{CurveName: "P-999"}}
	configObject.AllCaConfigs["test_ca_1"] = caConfig

	err := configObject.Validate()
	if !errors.Is(err, types.ErrInvalidCurve) {
		t.Errorf("expected ErrInvalidCurve, got %v", err)
	}
}

// P-224 was accepted here until a CA was found signing with one. A config that
// still names it is refused before a key is generated, and the error names the
// curves that are accepted instead.
func TestValidateConfigP224CurveIsErrInvalidCurve(t *testing.T) {
	configObject := validConfigFileData()
	caConfig := configObject.AllCaConfigs["test_ca_1"]
	caConfig.KeyConfig = types.KeyConfigType{Type: "ecdsa", Config: types.KeyTypeEcdsaConfigType{CurveName: "P-224"}}
	configObject.AllCaConfigs["test_ca_1"] = caConfig

	err := configObject.Validate()
	if !errors.Is(err, types.ErrInvalidCurve) {
		t.Fatalf("expected ErrInvalidCurve, got %v", err)
	}
	if !strings.Contains(err.Error(), "P-256, P-384, P-521") {
		t.Errorf("expected the error to name the accepted curves, got %v", err)
	}
}
