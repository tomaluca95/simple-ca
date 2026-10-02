package caissuingprocess

import (
	"context"
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
		logger.DebugContext(context.Background(), "generating new RSA private key", "filename", filename)
		newPrivateKey, err := rsa.GenerateKey(rand.Reader, keySize)
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

	logger.DebugContext(context.Background(), "reading RSA private key", "filename", filename)
	if err := ensurePrivateKeyFilePermissions(filename); err != nil {
		return nil, err
	}
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
