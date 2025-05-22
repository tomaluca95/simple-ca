package caissuingprocess

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

type OneCaType struct {
	caConfig              types.CertificateAuthorityType
	caPrivateKey          crypto.Signer
	caCertificate         *x509.Certificate
	caDir                 string
	dataDir               string
	crlIndexFilename      string
	csrSpoolDir           string
	issuedCertificatesDir string
	caFilenameCrl         string
	caFilenamePrivateKey  string

	logger types.Logger
}

func LoadOneCa(
	ctx context.Context,
	logger types.Logger,
	caId string,
	dataDirectory string,
	caConfig types.CertificateAuthorityType,
) (*OneCaType, error) {
	var oneCa OneCaType
	oneCa.logger = logger
	e := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	if !e.MatchString(caId) {
		return nil, fmt.Errorf("%w %#v", types.ErrInvalidCaId, caId)
	}

	oneCa.caConfig = caConfig

	absDataDirectory, err := filepath.Abs(dataDirectory)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(absDataDirectory); err != nil {
		return nil, fmt.Errorf("%s is not a directory", dataDirectory)
	}

	oneCa.caDir = filepath.Join(absDataDirectory, caId)

	oneCa.dataDir = filepath.Join(oneCa.caDir, "data")

	oneCa.crlIndexFilename = filepath.Join(oneCa.dataDir, "crl.yml")
	oneCa.csrSpoolDir = filepath.Join(oneCa.dataDir, "csr")
	oneCa.issuedCertificatesDir = filepath.Join(oneCa.dataDir, "crt")

	oneCa.caFilenameCrl = filepath.Join(oneCa.caDir, "ca.crl.pem")
	oneCa.caFilenamePrivateKey = filepath.Join(oneCa.caDir, "ca.key.pem")

	if err := os.MkdirAll(oneCa.caDir, os.FileMode(0o711)); err != nil {
		return nil, fmt.Errorf("%s: %w", oneCa.caDir, err)
	}
	if err := os.MkdirAll(oneCa.dataDir, os.FileMode(0o711)); err != nil {
		return nil, fmt.Errorf("%s: %w", oneCa.dataDir, err)
	}
	if err := os.MkdirAll(oneCa.csrSpoolDir, os.FileMode(0o755)); err != nil {
		return nil, fmt.Errorf("%s: %w", oneCa.csrSpoolDir, err)
	}
	if err := os.MkdirAll(oneCa.issuedCertificatesDir, os.FileMode(0o755)); err != nil {
		return nil, fmt.Errorf("%s: %w", oneCa.issuedCertificatesDir, err)
	}

	switch keyConfigData := oneCa.caConfig.KeyConfig.Config.(type) {
	case types.KeyTypeRsaConfigType:
		caPrivateKey, err := getRsaPrivateKeyOrCreateNew(
			logger,
			oneCa.caFilenamePrivateKey,
			keyConfigData.Size,
		)
		if err != nil {
			return nil, err
		}
		oneCa.caPrivateKey = caPrivateKey
	case types.KeyTypeEcdsaConfigType:
		caPrivateKey, err := getEcdsaPrivateKeyOrCreateNew(
			logger,
			oneCa.caFilenamePrivateKey,
			keyConfigData.CurveName,
		)
		if err != nil {
			return nil, err
		}
		oneCa.caPrivateKey = caPrivateKey
	default:
		return nil, fmt.Errorf("%w: %T", types.ErrInvalidKeyType, keyConfigData)
	}

	if err := oneCa.gitSnapshot(
		"loading root certificate",
		func() error {
			caCertificateTpl, err := getx509CaCertificateTpl(oneCa.caConfig)
			if err != nil {
				return err
			}
			caCertificate, err := getCertificateOrCreateNewSelfSigned(
				logger,
				oneCa.issuedCertificatesDir,
				caCertificateTpl,
				caCertificateTpl,
				oneCa.caPrivateKey,
			)
			if err != nil {
				return err
			}
			oneCa.caCertificate = caCertificate
			return nil
		},
	); err != nil {
		return nil, err
	}

	logger.Debug("Loaded CA: %s", oneCa.caCertificate.Issuer.String())

	return &oneCa, nil
}

func (oneCa *OneCaType) gitSnapshot(
	msg string,
	runner func() error,
) error {
	gitWorktree, err := gitOpenRepository(oneCa.dataDir)
	if err != nil {
		return err
	}
	if err := gitAddAndCommitGitWorktree(
		gitWorktree,
		"Before "+msg,
	); err != nil {
		return err
	}
	if err := runner(); err != nil {
		return err
	}
	if err := gitAddAndCommitGitWorktree(
		gitWorktree,
		"After "+msg,
	); err != nil {
		return err
	}
	return nil
}

func (oneCa *OneCaType) UpdateCrl() error {
	if err := oneCa.gitSnapshot(
		"crl update",
		func() error {
			if err := updateCrl(
				oneCa.crlIndexFilename,
				oneCa.caFilenameCrl,
				oneCa.caConfig.CrlTtl,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				[]*big.Int{},
			); err != nil {
				return err
			}
			return nil
		},
	); err != nil {
		return err
	}
	return nil
}

func (oneCa *OneCaType) IssueAllCsrInQueue() error {
	csrItems, err := os.ReadDir(oneCa.csrSpoolDir)
	if err != nil {
		return err
	}
	allErrors := []error{}
	for _, csrItem := range csrItems {
		csrFilename := filepath.Join(oneCa.csrSpoolDir, csrItem.Name())
		if _, err := oneCa.SignCsrFile(csrFilename); err != nil {
			allErrors = append(allErrors, err)
		}
	}
	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}
	return nil
}

func (oneCa *OneCaType) SignCsrFile(csrFilename string) ([]byte, error) {
	var pemBytes []byte
	if err := oneCa.gitSnapshot(
		"issuing "+csrFilename,
		func() error {

			newPemBytes, err := signOneCsr(
				oneCa.logger,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				csrFilename,
				oneCa.issuedCertificatesDir,
			)
			if err != nil {
				return err
			}
			pemBytes = newPemBytes
			return nil
		},
	); err != nil {
		return nil, err
	}
	return pemBytes, nil
}

func (oneCa *OneCaType) RevokeOneSerial(crtSerial *big.Int) error {
	if err := oneCa.gitSnapshot(
		"revoking "+crtSerial.String(),
		func() error {
			if err := updateCrl(
				oneCa.crlIndexFilename,
				oneCa.caFilenameCrl,
				oneCa.caConfig.CrlTtl,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				[]*big.Int{crtSerial},
			); err != nil {
				return err
			}
			return nil
		},
	); err != nil {
		return err
	}
	return nil
}

func (oneCa *OneCaType) GetCrlPem() ([]byte, error) {
	fileContent, err := os.ReadFile(oneCa.caFilenameCrl)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return fileContent, nil
}

func (oneCa *OneCaType) GetIssuerPem() ([]byte, error) {
	fileContent, err := pemhelper.ToPem(oneCa.caCertificate)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}
