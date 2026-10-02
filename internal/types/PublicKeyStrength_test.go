package types_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestPublicKeyIsAccepted(t *testing.T) {
	rsaKey := func(bits int) crypto.PublicKey {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return &key.PublicKey
	}
	ecdsaKey := func(curve elliptic.Curve) crypto.PublicKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &key.PublicKey
	}
	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		accepted  bool
	}{
		{"rsa 1024", rsaKey(1024), false},
		{"rsa 2048", rsaKey(2048), true},
		{"rsa 3072", rsaKey(3072), true},
		{"ecdsa P-224", ecdsaKey(elliptic.P224()), false},
		{"ecdsa P-256", ecdsaKey(elliptic.P256()), true},
		{"ecdsa P-384", ecdsaKey(elliptic.P384()), true},
		{"ecdsa P-521", ecdsaKey(elliptic.P521()), true},
		{"ecdsa without a curve", &ecdsa.PublicKey{}, false},
		{"ed25519", ed25519Private.Public(), true},
		// A key that cannot sign is not a key for a certificate that is meant
		// to be signed for, and its strength is not a question this check can
		// answer: it is refused.
		{"x25519", x25519Key.PublicKey(), false},
		{"unknown algorithm", struct{}{}, false},
		{"no key at all", nil, false},
	}
	for _, test := range tests {
		err := types.PublicKeyIsAccepted(test.publicKey)
		if test.accepted {
			if err != nil {
				t.Errorf("%s: expected accepted, got %v", test.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: expected refused, got accepted", test.name)
			continue
		}
		if !errors.Is(err, types.ErrWeakPublicKey) {
			t.Errorf("%s: expected %v, got %v", test.name, types.ErrWeakPublicKey, err)
		}
	}
}

// The curve a configuration may name and the curve a key is measured against
// have to be the same list, or a config can ask for a key the CA then refuses.
func TestApprovedCurvesAndTheCurvesAKeyIsMeasuredAgainstAreTheSame(t *testing.T) {
	approved := types.ApprovedEllipticCurves()
	if !slices.Contains(approved, "P-256") {
		t.Errorf("expected P-256 to be approved, got %v", approved)
	}
	// P-224 is 112-bit security and is not in NIST SP 800-186. It was
	// accepted here until a CA was found signing with one.
	if slices.Contains(approved, "P-224") {
		t.Errorf("expected P-224 not to be approved, got %v", approved)
	}
	for _, curveName := range approved {
		if !types.EllipticCurveIsApproved(curveName) {
			t.Errorf("%s: listed as approved but EllipticCurveIsApproved says no", curveName)
		}
	}
	for _, curveName := range []string{"P-224", "P-999", "", "p-256"} {
		if types.EllipticCurveIsApproved(curveName) {
			t.Errorf("expected %q not to be approved", curveName)
		}
	}
	// The list is a copy: a caller cannot widen it.
	approved[0] = "P-224"
	if types.EllipticCurveIsApproved("P-224") {
		t.Error("expected the approved curves to be a copy the caller cannot change")
	}
}
