package pemhelper

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
)

func ToPem(object interface{}) ([]byte, error) {
	switch typedObject := object.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(typedObject),
		}), nil
	case rsa.PrivateKey:
		return ToPem(&typedObject)
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(typedObject)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}), nil
	case ecdsa.PrivateKey:
		return ToPem(&typedObject)
	case *x509.Certificate:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: typedObject.Raw,
		}), nil
	case x509.Certificate:
		return ToPem(&typedObject)
	default:
		typeOf := reflect.TypeOf(typedObject)
		return nil, fmt.Errorf("%w : %#v", ErrPemInvalidObject, typeOf)
	}
}
