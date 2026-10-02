package caissuingprocess

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrInvalidCrlIndex reports an index file the CA cannot read as the single
// sequence of entries it writes: a second document, content after the first,
// or an entry that never says when its revocation stops mattering.
var ErrInvalidCrlIndex = errors.New("invalid CRL index")

// oneRevokedCertInfoType is one entry of the revocation index, crl.yml: a
// serial this CA revokes, when it was revoked, and when the revocation stops
// mattering. The last is what keeps the list from growing forever: a verifier
// rejects an expired certificate on its own, so once the certificate can no
// longer be valid its entry only makes the CRL bigger.
type oneRevokedCertInfoType struct {
	SerialNumber        *big.Int `yaml:"serial_number"`
	RevocationTime      int64    `yaml:"revocation_time"`
	RevocationExpiresAt int64    `yaml:"revocation_expires_at"`
}

// oneRevocationRequest is a serial this CA revokes now, with the instant after
// which the entry no longer matters: the earlier of the certificate's own
// notAfter and the CA's, which in practice is the certificate's, because
// issuance already caps a certificate's notAfter at its CA's.
type oneRevocationRequest struct {
	SerialNumber *big.Int
	ExpiresAt    time.Time
}

// readCrlIndex reads crl.yml as exactly the one document the tool writes, and
// nothing after it. A plain yaml.Unmarshal reads only the first document and
// silently ignores whatever follows: an entry appended under the empty index
// parsed as nothing, the index was rewritten without it, and a revocation the
// operator had made vanished with no error anywhere. A decoder, plus a
// required end of input, turns that into a refusal that names the file.
func readCrlIndex(crlIndexFilename string) ([]oneRevokedCertInfoType, error) {
	crlIndexContent, err := os.ReadFile(crlIndexFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(crlIndexContent))
	var revokedCertsInfo []oneRevokedCertInfoType
	if err := decoder.Decode(&revokedCertsInfo); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty file is an empty index, not a malformed one.
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidCrlIndex, crlIndexFilename, err)
	}

	var trailingContent any
	switch err := decoder.Decode(&trailingContent); {
	case errors.Is(err, io.EOF):
		return revokedCertsInfo, nil
	case err != nil:
		return nil, fmt.Errorf(
			"%w: %s: unexpected content after the index: %v",
			ErrInvalidCrlIndex, crlIndexFilename, err,
		)
	default:
		return nil, fmt.Errorf(
			"%w: %s: the index must be one sequence, but a second document follows it",
			ErrInvalidCrlIndex, crlIndexFilename,
		)
	}
}

func updateCrl(
	crlIndexFilename string,
	caFilenameCrl string,
	crlTtl time.Duration,
	clockSkew time.Duration,
	caCertificate *x509.Certificate,
	caPrivateKey crypto.Signer,
	addRevocations []oneRevocationRequest,
) error {
	crlList := []x509.RevocationListEntry{}
	var newCrlIndexContent []byte

	{
		revokedCertsInfo, err := readCrlIndex(crlIndexFilename)
		if err != nil {
			return err
		}

		nowMillis := time.Now().UnixMilli()
		for _, revocation := range addRevocations {
			revokedCertsInfo = append(revokedCertsInfo, oneRevokedCertInfoType{
				SerialNumber:        revocation.SerialNumber,
				RevocationTime:      nowMillis,
				RevocationExpiresAt: revocation.ExpiresAt.UTC().UnixMilli(),
			})
		}

		// Every entry is checked before anything is sorted, written or signed,
		// so a hand-edited entry cannot reach a comparison it does not survive
		// and cannot be written back before it is refused.
		//
		// The index is a file in the data directory and entries reach it
		// without going through the revoking paths, so it is checked on the way
		// into the CRL rather than on the way in: a serial added by hand cannot
		// be this CA's own, or this CA would publish a CRL revoking itself and
		// keep serving the certificate. Other serials are left alone: an entry
		// naming a serial this CA never issued matches no certificate, so it
		// cannot mislead anyone into distrusting one.
		for _, revokedCertInfo := range revokedCertsInfo {
			if revokedCertInfo.SerialNumber == nil {
				return fmt.Errorf("%w: an entry in %s has no serial number", ErrCannotRevokeCaCertificate, crlIndexFilename)
			}
			if revokedCertInfo.SerialNumber.Cmp(caCertificate.SerialNumber) == 0 {
				return fmt.Errorf(
					"%w: serial %s in %s is the CA certificate itself",
					ErrCannotRevokeCaCertificate,
					caCertificate.SerialNumber.String(),
					crlIndexFilename,
				)
			}
			// An entry an operator wrote has to say when it stops mattering:
			// only the operator knows, and refusing it by name is better than
			// guessing, dropping it, or keeping it forever.
			if revokedCertInfo.RevocationExpiresAt == 0 {
				return fmt.Errorf(
					"%w: serial %s in %s has no revocation_expires_at",
					ErrInvalidCrlIndex,
					revokedCertInfo.SerialNumber.String(),
					crlIndexFilename,
				)
			}
		}

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

		survivors := make([]oneRevokedCertInfoType, 0, len(revokedCertsInfo))
		for _, revokedCertInfo := range revokedCertsInfo {
			// A revocation stops mattering when the certificate it names can no
			// longer be valid. It leaves the published list and the index here;
			// the git history keeps the record of it.
			if revokedCertInfo.RevocationExpiresAt <= nowMillis {
				continue
			}
			survivors = append(survivors, revokedCertInfo)
			crlList = append(crlList, x509.RevocationListEntry{
				SerialNumber:   revokedCertInfo.SerialNumber,
				RevocationTime: time.UnixMilli(revokedCertInfo.RevocationTime),
			})
		}

		commentPrefixToIndex := []byte(`# - serial_number: "1"
#   revocation_time: 1714575000000 # unix time millis
#   revocation_expires_at: 1727200000000 # unix time millis
`)
		newCrlIndexYamlContent, err := yaml.Marshal(survivors)
		if err != nil {
			return err
		}
		newCrlIndexContent = append(commentPrefixToIndex, newCrlIndexYamlContent...)
	}

	now := time.Now()
	crlTemplate := &x509.RevocationList{
		NextUpdate:                now.Add(crlTtl),
		Issuer:                    caCertificate.Issuer,
		AuthorityKeyId:            caCertificate.AuthorityKeyId,
		ThisUpdate:                now.Add(-clockSkew),
		RevokedCertificateEntries: crlList,
		// The number comes from the clock, not from the CRL on disk. Reading the
		// old one to advance it is what made an unparseable ca.crl.pem refuse
		// every load, over the very file this call is about to replace. The rest
		// of the CRL is wall-clock anyway -- ThisUpdate and NextUpdate are this
		// same now -- so a number from it assumes no more of the clock than the
		// CRL already does, and it rises on its own.
		Number: big.NewInt(now.UnixMilli()),
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

	// The published CRL is written before the index, so the index only ever
	// records a revocation the CA has already issued a CRL for. The write used
	// to come first: an entry the validation then rejected -- a null serial, or
	// the CA's own -- was already on disk, and every later load read the refusal
	// back, so the CA could not start until an operator edited the index by
	// hand. The index now changes only once the CRL that carries its entries
	// has been written, and a rejected entry leaves it exactly as it was.
	if err := atomicWriteFile(caFilenameCrl, pemBlockBytes, os.FileMode(0o644)); err != nil {
		return err
	}
	return atomicWriteFile(crlIndexFilename, newCrlIndexContent, os.FileMode(0o644))
}
