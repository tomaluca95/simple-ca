package types_test

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestValidityNotAfterIsAnIsoTimestamp(t *testing.T) {
	// Both spellings a hand-written config uses, and both naming the same
	// instant: yaml resolves an unquoted timestamp itself, a quoted one arrives
	// as a string and is parsed strictly.
	for _, notAfter := range []string{"2027-10-01T00:00:00Z", `"2027-10-01T00:00:00Z"`} {
		config := decodeConfig(t, "validity:\n    not_after: "+notAfter+"\n")
		want := time.Date(2027, time.October, 1, 0, 0, 0, 0, time.UTC)
		if !config.Validity.NotAfter.Equal(want) {
			t.Errorf("not_after %s decoded as %s, want %s", notAfter, config.Validity.NotAfter, want)
		}
	}

	// An offset written out is the same instant, not a different one: the tool
	// asks for ISO 8601 with a zone, and UTC is what it stores and reports.
	config := decodeConfig(t, "validity:\n    not_after: 2027-10-01T02:00:00+02:00\n")
	want := time.Date(2027, time.October, 1, 0, 0, 0, 0, time.UTC)
	if !config.Validity.NotAfter.Equal(want) {
		t.Errorf("not_after with an offset decoded as %s, want the instant %s", config.Validity.NotAfter, want)
	}
}

func TestValidityRejectsWhatIsNotAnIsoTimestamp(t *testing.T) {
	// Each of these is a shape yaml would have accepted for a time.Time, and
	// each of them leaves the instant to be guessed: a bare date, a local time
	// with no zone, a duration, a number, and a typo.
	for name, notAfter := range map[string]string{
		"date only":            "2027-10-01",
		"no time zone":         "2027-10-01 00:00:00",
		"no seconds":           "2027-10-01T00:00Z",
		"a duration":           "8760h",
		"a bare number":        "20271001",
		"not a date at all":    "next october",
		"quoted date only":     `"2027-10-01"`,
		"empty":                `""`,
		"an unquoted duration": "24h",
	} {
		t.Run(name, func(t *testing.T) {
			decoder := yaml.NewDecoder(strings.NewReader("validity:\n    not_after: " + notAfter + "\n"))
			decoder.KnownFields(true)
			var config types.CertificateAuthorityType
			err := decoder.Decode(&config)
			if err == nil {
				t.Fatalf("expected %s to be refused, decoded as %s", notAfter, config.Validity.NotAfter)
			}
			if !strings.Contains(err.Error(), "is not an ISO 8601 timestamp with a time zone") {
				t.Errorf("expected a format report, got %v", err)
			}
		})
	}
}

func TestValidityRefusesAnyKeyButNotAfter(t *testing.T) {
	// There is one shape, and it is not_after: a config that asks for a
	// lifetime by any other name is an invalid config, not an old one to be
	// carried along. The report is the plain unknown-field one, the same an
	// unknown key anywhere else in the config gets.
	for _, key := range []string{"years: 2", "months: 1", "days: 30", "expires: 2027-10-01T00:00:00Z"} {
		t.Run(key, func(t *testing.T) {
			decoder := yaml.NewDecoder(strings.NewReader("validity:\n    " + key + "\n"))
			decoder.KnownFields(true)
			var config types.CertificateAuthorityType
			err := decoder.Decode(&config)
			if err == nil {
				t.Fatalf("expected validity.%s to be refused", strings.Split(key, ":")[0])
			}
			field := strings.TrimSpace(strings.Split(key, ":")[0])
			if !strings.Contains(err.Error(), "field "+field+" not found in type types.CertificateAuthorityValidityType") {
				t.Errorf("expected the plain unknown-field report, got %v", err)
			}
		})
	}
}

func TestValidityRejectsAMappingWithoutNotAfter(t *testing.T) {
	// Absent, the expiry is zero, and the report from Validate names it. A CA
	// with no declared expiry is not a CA with an open-ended one.
	decoder := yaml.NewDecoder(strings.NewReader("validity: {}\n"))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	if err := decoder.Decode(&config); err != nil {
		t.Fatal(err)
	}
	if !config.Validity.NotAfter.IsZero() {
		t.Fatalf("expected no expiry, got %s", config.Validity.NotAfter)
	}
	// The bare config reports other problems too, so the expiry is looked for
	// among all of them rather than in a position.
	reported := false
	for _, problem := range config.Validate() {
		if strings.Contains(problem.Error(), "validity.not_after must be an ISO 8601 timestamp") {
			reported = true
		}
	}
	if !reported {
		t.Error("expected a problem for a CA with no declared expiry, got none naming validity.not_after")
	}
}

func TestValidityRejectsSomethingThatIsNotAMapping(t *testing.T) {
	decoder := yaml.NewDecoder(strings.NewReader("validity: 12h\n"))
	decoder.KnownFields(true)
	var config types.CertificateAuthorityType
	err := decoder.Decode(&config)
	if err == nil {
		t.Fatal("expected a scalar validity to be refused")
	}
	if !strings.Contains(err.Error(), "validity must be a mapping with a not_after key") {
		t.Errorf("expected a shape report, got %v", err)
	}
}
