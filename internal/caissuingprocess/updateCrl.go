package caissuingprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

func updateCrl(
	crlIndexFilename string,
	caFilenameCrl string,
	crlTtl time.Duration,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
	addSerialsToRevoked []*big.Int,
) error {
	crlList := []pkix.RevokedCertificate{}

	{
		type oneRevokedCertInfoType struct {
			SerialNumber   *big.Int `yaml:"serial_number"`
			RevocationTime int64    `yaml:"revocation_time"`
		}
		var revokedCertsInfo []oneRevokedCertInfoType

		crlIndexContent, err := os.ReadFile(crlIndexFilename)
		if err != nil && !os.IsNotExist(err) {
			return err
		} else {
			if err := yaml.Unmarshal(crlIndexContent, &revokedCertsInfo); err != nil {
				return err
			}
		}
		for _, oneSerialToRevoke := range addSerialsToRevoked {
			revokedCertsInfo = append(revokedCertsInfo, oneRevokedCertInfoType{
				SerialNumber:   oneSerialToRevoke,
				RevocationTime: time.Now().UnixMilli(),
			})
		}

		{
			sort.Slice(revokedCertsInfo, func(i, j int) bool {
				cmpResult := revokedCertsInfo[i].SerialNumber.Cmp(revokedCertsInfo[j].SerialNumber)
				if cmpResult < 0 {
					return true
				} else if cmpResult == 0 {
					return revokedCertsInfo[i].RevocationTime < revokedCertsInfo[j].RevocationTime
				} else {
					return false
				}
			})

			{
				i := 0
				for i < len(revokedCertsInfo)-1 {
					if revokedCertsInfo[i].SerialNumber.Cmp(revokedCertsInfo[i+1].SerialNumber) == 0 {
						revokedCertsInfo = append(revokedCertsInfo[:i+1], revokedCertsInfo[i+2:]...)
					} else {
						i++
					}
				}
			}

			commentPrefixToIndex := []byte(`# - serial_number: "1"
#   revocation_time: 1714575000000 # unix time millis
`)
			newCrlIndexYamlContent, err := yaml.Marshal(revokedCertsInfo)
			if err != nil {
				return err
			}

			newCrlIndexContent := append(commentPrefixToIndex, newCrlIndexYamlContent...)

			if err := os.WriteFile(crlIndexFilename, newCrlIndexContent, os.FileMode(0o644)); err != nil {
				return err
			}
		}

		for _, revokedCertInfo := range revokedCertsInfo {
			crlList = append(crlList, pkix.RevokedCertificate{
				SerialNumber:   revokedCertInfo.SerialNumber,
				RevocationTime: time.UnixMilli(revokedCertInfo.RevocationTime),
			})
		}
	}

	crlTemplate := &x509.RevocationList{
		NextUpdate:          time.Now().Add(crlTtl),
		Issuer:              caCertificate.Issuer,
		AuthorityKeyId:      caCertificate.AuthorityKeyId,
		ThisUpdate:          time.Now(),
		RevokedCertificates: crlList,
		Number:              big.NewInt(time.Now().UnixMilli()),
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		crlTemplate,
		caCertificate,
		caPrivateKey,
	)
	if err != nil {
		return err
	}
	pemBlockBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	if err := os.WriteFile(caFilenameCrl, pemBlockBytes, os.FileMode(0o644)); err != nil {
		return err
	}
	return nil
}
