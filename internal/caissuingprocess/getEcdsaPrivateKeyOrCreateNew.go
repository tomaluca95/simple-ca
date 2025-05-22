package caissuingprocess

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

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
		logger.Debug("Generate new key for %s", filename)
		var c elliptic.Curve
		switch curveName {
		case "P-224":
			c = elliptic.P224()
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("%w: %s", types.ErrInvalidCurve, curveName)
		}

		newPrivateKey, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, err
		}
		pemBytes, err := pemhelper.ToPem(newPrivateKey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, pemBytes, os.FileMode(0o644)); err != nil {
			return nil, err
		}
	}

	logger.Debug("Reading file %s", filename)
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
