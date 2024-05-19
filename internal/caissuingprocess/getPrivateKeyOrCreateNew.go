package caissuingprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
)

var ErrUnsupportedChangeToKeySize = fmt.Errorf("invalid key size")

func getRsaPrivateKeyOrCreateNew(
	filename string,
	keySize int,
) (crypto.Signer, error) {
	if _, err := os.Stat(filename); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		log.Println("Generate new key for " + filename)
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

	log.Println("Reading file " + filename)
	privateKeyContent, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privateKey, err := pemhelper.FromPemToRsaPrivateKey(privateKeyContent)
	if err != nil {
		return nil, err
	}

	if foundKeySize := privateKey.N.BitLen(); foundKeySize != keySize {
		return nil, fmt.Errorf("%w %d is not %d", ErrUnsupportedChangeToKeySize, foundKeySize, keySize)
	}
	return privateKey, nil
}
