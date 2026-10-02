package caissuingprocess

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func getEcdsaPrivateKeyOrCreateNew(
	logger types.Logger,
	filename string,
	curveName string,
) (crypto.Signer, error) {
	if _, err := os.Stat(filename); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		logger.DebugContext(context.Background(), "generating new ECDSA private key", "filename", filename)
		var c elliptic.Curve
		switch curveName {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			// A curve this CA does not accept is not generated, so a key on one
			// can only be a key an earlier release left behind.
			return nil, fmt.Errorf("%w: %q is not one of %s", types.ErrInvalidCurve, curveName, strings.Join(types.ApprovedEllipticCurves(), ", "))
		}

		newPrivateKey, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, err
		}
		pemBytes, err := pemhelper.ToPem(newPrivateKey)
		if err != nil {
			return nil, err
		}
		if err := atomicWriteFile(filename, pemBytes, os.FileMode(0o600)); err != nil {
			return nil, err
		}
	}

	logger.DebugContext(context.Background(), "reading ECDSA private key", "filename", filename)
	if err := ensurePrivateKeyFilePermissions(filename); err != nil {
		return nil, err
	}
	privateKeyContent, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privateKey, err := pemhelper.FromPemToEcdsaPrivateKey(privateKeyContent)
	if err != nil {
		return nil, err
	}

	if foundCurveName := privateKey.Curve.Params().Name; foundCurveName != curveName {
		return nil, fmt.Errorf("%w %s is not %s", types.ErrUnsupportedChangeToCurve, foundCurveName, curveName)
	}
	return privateKey, nil
}
