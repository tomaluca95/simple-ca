package types

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// CertificateAuthorityValidityType is when the CA's own certificate stops being
// valid: an absolute instant, written as an ISO 8601 timestamp.
//
// It is absolute on purpose. A lifetime expressed as a distance from the moment
// the tool happens to run is not a fact about the CA, it is a different fact
// every time it is recomputed, and one that moves with the calendar rather than
// with the CA: "one month from now" is thirty days on the 30th and thirty-one
// days on the 1st. Declared as an instant, the value a load compares against is
// the same on every day the tool runs on.
type CertificateAuthorityValidityType struct {
	NotAfter time.Time `yaml:"not_after"`
}

// UnmarshalYAML reads validity.not_after as an ISO 8601 timestamp, and nothing
// else. The strictness is the point: a lifetime is the one field a CA operator
// has to be able to read back and reason about, and a value accepted in several
// shapes, with an implied zone and a resolution nobody wrote down, is not that.
func (validity *CertificateAuthorityValidityType) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("validity must be a mapping with a not_after key")
	}

	*validity = CertificateAuthorityValidityType{}
	for i := 0; i < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		if keyNode.Value != "not_after" {
			return fmt.Errorf("field %s not found in type types.CertificateAuthorityValidityType", keyNode.Value)
		}
		notAfter, err := parseNotAfter(valueNode)
		if err != nil {
			return err
		}
		validity.NotAfter = notAfter
	}
	return nil
}

// parseNotAfter accepts an ISO 8601 timestamp whose time zone is written out.
// Formats that leave the offset implied -- a bare date, or a local time with no
// zone -- are refused rather than guessed at: the same config read on two
// machines must name the same instant on both.
func parseNotAfter(node *yaml.Node) (time.Time, error) {
	quoted := node.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
	if !quoted && node.Tag != "!!timestamp" {
		return time.Time{}, notAfterFormatError(node.Value)
	}
	notAfter, err := time.Parse(time.RFC3339, node.Value)
	if err != nil {
		return time.Time{}, notAfterFormatError(node.Value)
	}
	return notAfter, nil
}

func notAfterFormatError(value string) error {
	return fmt.Errorf(
		"validity.not_after %q is not an ISO 8601 timestamp with a time zone, for example 2027-10-01T00:00:00Z",
		value,
	)
}
