package caissuingprocess

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

func extractPublicKeyFromSigner(signer crypto.Signer) any {
	switch signerTyped := signer.(type) {
	case *rsa.PrivateKey:
		return &signerTyped.PublicKey
	default:
		panic(fmt.Errorf("invalid key type: %T", signerTyped))
	}
}
