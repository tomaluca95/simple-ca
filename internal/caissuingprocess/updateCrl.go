package caissuingprocess

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

			if err := atomicWriteFile(crlIndexFilename, newCrlIndexContent, os.FileMode(0o644)); err != nil {
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

	nextCrlNumber, err := getNextCrlNumber(caFilenameCrl)
	if err != nil {
		return err
	}

	crlTemplate := &x509.RevocationList{
		NextUpdate:          time.Now().Add(crlTtl),
		Issuer:              caCertificate.Issuer,
		AuthorityKeyId:      caCertificate.AuthorityKeyId,
		ThisUpdate:          time.Now(),
		RevokedCertificates: crlList,
		Number:              nextCrlNumber,
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

	if err := atomicWriteFile(caFilenameCrl, pemBlockBytes, os.FileMode(0o644)); err != nil {
		return err
	}
	return nil
}

func getNextCrlNumber(caFilenameCrl string) (*big.Int, error) {
	defaultCrlNumber := big.NewInt(time.Now().UnixMilli())

	crlPemBytes, err := os.ReadFile(caFilenameCrl)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultCrlNumber, nil
		}
		return nil, err
	}

	pemBlock, _ := pem.Decode(crlPemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid CRL PEM content in %s", caFilenameCrl)
	}

	parsedCrl, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CRL content in %s: %w", caFilenameCrl, err)
	}

	if parsedCrl.Number == nil {
		return defaultCrlNumber, nil
	}

	nextCrlNumber := new(big.Int).Set(parsedCrl.Number)
	nextCrlNumber.Add(nextCrlNumber, big.NewInt(1))
	return nextCrlNumber, nil
}

func atomicWriteFile(filename string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tmpFilename := tmpFile.Name()
	defer os.Remove(tmpFilename)

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(mode); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpFilename, filename); err != nil {
		return err
	}

	// Persist directory entry update (rename) for crash safety.
	dirFd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFd.Close()

	if err := dirFd.Sync(); err != nil {
		return err
	}
	return nil
}
