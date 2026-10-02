package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
)

// MinRsaPublicKeyBits is the smallest RSA key this CA will sign with or certify.
// NIST SP 800-57 part 1 rev. 5 places the security strength of anything below
// 2048 bits at 112 bits or less, and 1024 bits has been below every browser and
// CA/B forum baseline since 2013.
const MinRsaPublicKeyBits = 2048

// approvedEllipticCurves are the curves a key of this CA, or of a certificate
// it issues, may be on: the ones NIST SP 800-186 approves.
//
// P-224 is left out on purpose. It is not on that list, at 112 bits it is the
// weakest curve Go still signs with without a word of complaint, and it was
// accepted here until it was found signing in production, so a CA left on one
// by an earlier release is refused at load time now.
var approvedEllipticCurves = []string{"P-256", "P-384", "P-521"}

// ApprovedEllipticCurves returns the curve names this CA accepts, for the error
// messages that have to name them.
func ApprovedEllipticCurves() []string {
	approved := make([]string, len(approvedEllipticCurves))
	copy(approved, approvedEllipticCurves)
	return approved
}

// EllipticCurveIsApproved reports whether a curve name is one this CA accepts.
// A configuration is checked against it, so a config cannot ask for a key the CA
// would then refuse to load.
func EllipticCurveIsApproved(curveName string) bool {
	for _, approved := range approvedEllipticCurves {
		if curveName == approved {
			return true
		}
	}
	return false
}

// PublicKeyIsAccepted reports whether a public key is strong enough for this CA
// to sign with, or to certify, so a weak key is refused whether it arrives in a
// configuration, in a data directory left by an earlier release, or in a CSR.
//
// The same check is deliberately used for both ends of a chain. A CA whose own
// key is weak undermines every certificate it issues, and one whose key
// strength rule is looser than the one it applies to clients is a CA that
// certifies chains it would not sign itself.
//
// A key of an algorithm not named here is refused rather than waved through, so
// teaching a parser a new algorithm cannot quietly widen what this CA signs.
func PublicKeyIsAccepted(publicKey crypto.PublicKey) error {
	switch typed := publicKey.(type) {
	case *rsa.PublicKey:
		if bits := typed.N.BitLen(); bits < MinRsaPublicKeyBits {
			return fmt.Errorf(
				"%w: RSA %d bits, the minimum is %d",
				ErrWeakPublicKey,
				bits,
				MinRsaPublicKeyBits,
			)
		}
		return nil
	case *ecdsa.PublicKey:
		// Compared by name, the same way a configuration is, so a key and the
		// config that describes it cannot disagree about what is approved.
		curveName := ellipticCurveName(typed.Curve)
		if EllipticCurveIsApproved(curveName) {
			return nil
		}
		return fmt.Errorf(
			"%w: ECDSA curve %s, the accepted curves are %s",
			ErrWeakPublicKey,
			curveName,
			strings.Join(ApprovedEllipticCurves(), ", "),
		)
	case ed25519.PublicKey:
		// Ed25519 is only ever 256 bits, and Go has no way to build a weaker
		// one, so there is nothing to measure here.
		return nil
	default:
		return fmt.Errorf(
			"%w: %T is not an accepted algorithm",
			ErrWeakPublicKey,
			publicKey,
		)
	}
}

func ellipticCurveName(curve elliptic.Curve) string {
	if curve == nil {
		return "unknown"
	}
	return curve.Params().Name
}
