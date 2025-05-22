package caissuingprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func getRsaPrivateKeyOrCreateNew(
	logger types.Logger,
	filename string,
	keySize int,
) (crypto.Signer, error) {
	if _, err := os.Stat(filename); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		logger.Debug("Generate new key for %s", filename)
		newPrivateKey, err := rsa.GenerateKey(rand.Reader, keySize)
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
	privateKey, err := pemhelper.FromPemToRsaPrivateKey(privateKeyContent)
	if err != nil {
		return nil, err
	}

	if foundKeySize := privateKey.N.BitLen(); foundKeySize != keySize {
		return nil, fmt.Errorf("%w %d is not %d", types.ErrUnsupportedChangeToKeySize, foundKeySize, keySize)
	}
	return privateKey, nil
}
