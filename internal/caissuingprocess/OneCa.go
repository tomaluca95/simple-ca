package caissuingprocess

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/tomaluca95/simple-ca/internal/opa"
	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

var ErrUnknownSerial = errors.New("unknown serial")
var ErrCaCertificateMismatch = errors.New("CA certificate does not match the configuration")
var ErrCaCertificateAlreadyExpired = errors.New("the configured CA expiry is not in the future")
var ErrCaKeyMismatch = errors.New("CA private key does not match the CA certificate")
var ErrRevokeSerialMismatch = errors.New("the file stored for this serial holds a different certificate")

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

	mu sync.Mutex

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
	e := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	if !e.MatchString(caId) {
		return nil, fmt.Errorf("%w %#v", types.ErrInvalidCaId, caId)
	}

	// Every log record of this CA is tagged with its caId.
	oneCa.logger = logger.With("ca_id", caId)

	oneCa.caConfig = caConfig

	absDataDirectory, err := filepath.Abs(dataDirectory)
	if err != nil {
		return nil, err
	}

	dataDirectoryInfo, err := os.Stat(absDataDirectory)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", dataDirectory, err)
		}
		if err := os.MkdirAll(absDataDirectory, os.FileMode(0o711)); err != nil {
			return nil, fmt.Errorf("%s: %w", dataDirectory, err)
		}
	} else if !dataDirectoryInfo.IsDir() {
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

	caCertificateTpl, err := getx509CaCertificateTpl(oneCa.caConfig)
	if err != nil {
		return nil, err
	}
	caCertificateFilename := filepath.Join(
		oneCa.issuedCertificatesDir,
		caCertificateTpl.SerialNumber.String()+".crt.pem",
	)

	// The key and the certificate are created together, so a certificate next to
	// a missing key means the key was lost. Generating a new one here would
	// quietly replace the CA with one that cannot sign for the certificate
	// clients already trust, so it is refused and the operator is told which
	// two files belong together.
	if err := caKeyPresentForCertificate(
		oneCa.caFilenamePrivateKey,
		caCertificateFilename,
	); err != nil {
		return nil, err
	}

	switch keyConfigData := oneCa.caConfig.KeyConfig.Config.(type) {
	case types.KeyTypeRsaConfigType:
		caPrivateKey, err := getRsaPrivateKeyOrCreateNew(
			oneCa.logger,
			oneCa.caFilenamePrivateKey,
			keyConfigData.Size,
		)
		if err != nil {
			return nil, err
		}
		oneCa.caPrivateKey = caPrivateKey
	case types.KeyTypeEcdsaConfigType:
		caPrivateKey, err := getEcdsaPrivateKeyOrCreateNew(
			oneCa.logger,
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

	// The key that will sign is measured, not the name in the configuration:
	// a CA left on a key an earlier release accepted is refused here rather
	// than kept in service, since everything it signs, and every CRL it
	// publishes, is only as strong as this key. It is checked before the
	// certificate is read, so a CA with a key it may not use never gets as
	// far as publishing one.
	if err := types.PublicKeyIsAccepted(oneCa.caPrivateKey.Public()); err != nil {
		return nil, fmt.Errorf("CA key %s: %w", oneCa.caFilenamePrivateKey, err)
	}

	if err := oneCa.gitCommitState(
		"load CA",
		func() error {
			caCertificate, err := getCertificateOrCreateNewSelfSigned(
				oneCa.logger,
				oneCa.issuedCertificatesDir,
				caCertificateTpl,
				caCertificateTpl,
				oneCa.caPrivateKey,
			)
			if err != nil {
				return err
			}
			// Checked on every load, including a CA created by this very
			// call, so a CA only ever serves with a key that matches the
			// certificate it publishes.
			if err := caPrivateKeyMatchesCertificate(
				oneCa.caPrivateKey,
				caCertificate,
				oneCa.caFilenamePrivateKey,
				caCertificateFilename,
			); err != nil {
				return err
			}
			oneCa.caCertificate = caCertificate
			return nil
		},
	); err != nil {
		return nil, err
	}

	if err := oneCa.gitCommitState(
		"crl update",
		func() error {
			if err := updateCrl(
				oneCa.crlIndexFilename,
				oneCa.caFilenameCrl,
				oneCa.caConfig.CrlTtl,
				oneCa.caConfig.ClockSkew,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				nil,
			); err != nil {
				return err
			}
			return nil
		},
	); err != nil {
		return nil, err
	}

	oneCa.logger.InfoContext(ctx, "loaded CA", "issuer", oneCa.caCertificate.Issuer.String())

	return &oneCa, nil
}

// gitCommitState runs one state change and records the CA's meaningful state,
// plus any paths the change produced, as a single commit. The CA certificate
// and the revocation index are always included, and the file list stays small,
// so a commit's tree does not grow with the certificates the CA has issued.
// The change runs under the CA lock, so state updates stay serialized.
func (oneCa *OneCaType) gitCommitState(
	msg string,
	runner func() error,
	extraPaths ...string,
) error {
	oneCa.mu.Lock()
	defer oneCa.mu.Unlock()

	if err := runner(); err != nil {
		return err
	}

	caCertificateRelPath := filepath.Join(
		gitCertificatesDirName,
		oneCa.caCertificate.SerialNumber.String()+".crt.pem",
	)

	// The .gitignore keeps the rest of the working set out of `git status`,
	// which is why the on-disk certificates are not listed as untracked.
	gitignorePath := filepath.Join(oneCa.dataDir, gitIgnoreFilename)
	if err := atomicWriteFile(
		gitignorePath,
		[]byte(gitIgnoreContents(caCertificateRelPath)),
		os.FileMode(0o644),
	); err != nil {
		return err
	}

	paths := []string{
		gitIgnoreFilename,
		caCertificateRelPath,
		gitCRLIndexFilename,
	}
	paths = append(paths, extraPaths...)

	repo, gitWorktree, err := gitOpenRepository(oneCa.dataDir)
	if err != nil {
		return err
	}
	return gitCommitStateWorktree(repo, gitWorktree, msg, paths)
}

func (oneCa *OneCaType) UpdateCrl() error {
	if err := oneCa.gitCommitState(
		"crl update",
		func() error {
			if err := updateCrl(
				oneCa.crlIndexFilename,
				oneCa.caFilenameCrl,
				oneCa.caConfig.CrlTtl,
				oneCa.caConfig.ClockSkew,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				nil,
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

// signatureFailedDirName is where a CSR lands when it fails in a way another
// run cannot fix: the policy refused it, its signature or lifetime is invalid,
// or the authorizer is nil. Moving it out of the spool keeps the next run from
// failing for the same reason again, and the reason stays in the log line so
// the operator can find and repair the entry.
const signatureFailedDirName = "signature-failed"

// maxSpooledCsrBytes is the largest spool entry the CA will read. A CSR is a
// few kilobytes at most, and the HTTP path caps a sign request at the same
// size, so a spool entry past it is not a CSR this CA would have accepted
// anyway. The cap exists so one entry cannot decide how much memory a run uses.
const maxSpooledCsrBytes = 32 * 1024

// IssueAllCsrInQueue signs every entry the spool holds. An entry that fails in
// a way another run cannot fix is moved to the signature-failed directory and
// reported; an entry that fails transiently stays in the spool, is logged, and
// is retried on the next run; directories, entries that are not regular files
// or are larger than a CSR, and files that are not PEM are left where they are
// and skipped. Every reported error names its entry.
func (oneCa *OneCaType) IssueAllCsrInQueue(ctx context.Context, authorize SignAuthorizer) error {
	csrItems, err := os.ReadDir(oneCa.csrSpoolDir)
	if err != nil {
		return err
	}
	allErrors := []error{}
	for _, csrItem := range csrItems {
		if csrItem.IsDir() {
			if csrItem.Name() != signatureFailedDirName {
				oneCa.logger.WarnContext(ctx, "skipping a directory in the CSR spool", "name", csrItem.Name())
			}
			continue
		}

		csrFilename := filepath.Join(oneCa.csrSpoolDir, csrItem.Name())

		// The entry is inspected before it is read, because a whole spool
		// entry goes into memory. One that is not a regular file is skipped --
		// a FIFO blocks the read forever and a device reads without end -- and
		// so is one larger than a CSR can be. The HTTP path caps a sign
		// request at the same size, so neither can be a CSR the CA would have
		// accepted. Both are left where they are, like any other stray file.
		csrFileInfo, err := os.Stat(csrFilename)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("%s: %w", csrItem.Name(), err))
			continue
		}
		if !csrFileInfo.Mode().IsRegular() {
			oneCa.logger.WarnContext(ctx,
				"skipping a CSR spool entry that is not a regular file",
				"name", csrItem.Name(),
				"mode", csrFileInfo.Mode().String(),
			)
			continue
		}
		if csrFileInfo.Size() > maxSpooledCsrBytes {
			oneCa.logger.WarnContext(ctx,
				"skipping a CSR spool entry larger than a CSR can be",
				"name", csrItem.Name(),
				"size", csrFileInfo.Size(),
				"max_bytes", maxSpooledCsrBytes,
			)
			continue
		}

		// A stray file in the spool is not a CSR and cannot become one: leave
		// it where it is, but do not let it hold up the queue.
		fileContent, err := os.ReadFile(csrFilename)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("%s: %w", csrItem.Name(), err))
			continue
		}
		if pemBlock, _ := pem.Decode(fileContent); pemBlock == nil {
			oneCa.logger.DebugContext(ctx, "skipping a non-PEM file in the CSR spool", "name", csrItem.Name())
			continue
		}

		if _, err := oneCa.SignCsrFile(ctx, csrFilename, nil, authorize); err != nil {
			if isPermanentSigningError(err) {
				if moveErr := oneCa.moveFailedCsr(ctx, csrFilename, err); moveErr != nil {
					allErrors = append(allErrors,
						fmt.Errorf("%s: %w, then %v", csrItem.Name(), err, moveErr),
					)
					continue
				}
				allErrors = append(allErrors, fmt.Errorf("%s: %w", csrItem.Name(), err))
				continue
			}
			oneCa.logger.WarnContext(ctx, "keeping a CSR in the spool to retry", "csr", csrItem.Name(), "err", err)
			allErrors = append(allErrors, fmt.Errorf("%s: %w", csrItem.Name(), err))
		}
	}
	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}
	return nil
}

// moveFailedCsr moves a CSR that failed permanently out of the spool, into the
// signature-failed directory, and logs the reason next to the entry name. The
// destination keeps the entry's name, replacing an older copy of the same
// name: only the newest refusal is worth keeping.
func (oneCa *OneCaType) moveFailedCsr(ctx context.Context, csrFilename string, err error) error {
	failedDir := filepath.Join(oneCa.csrSpoolDir, signatureFailedDirName)
	if err := os.MkdirAll(failedDir, os.FileMode(0o755)); err != nil {
		return fmt.Errorf("creating %s: %w", failedDir, err)
	}
	destination := filepath.Join(failedDir, filepath.Base(csrFilename))
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", destination, err)
	}
	if err := os.Rename(csrFilename, destination); err != nil {
		return fmt.Errorf("moving to %s: %w", destination, err)
	}
	oneCa.logger.WarnContext(ctx, "signature failed: moved out of the spool", "csr", filepath.Base(csrFilename), "err", err)
	return nil
}

// isPermanentSigningError reports whether a signing failure will outlive a
// retry: an invalid CSR or lifetime is the entry's own fault, a nil authorizer
// is a configuration fault, and a refused authorization is the policy's
// verdict on this very entry. Anything else is kept in the spool and retried.
func isPermanentSigningError(err error) bool {
	return errors.Is(err, ErrInvalidCsr) ||
		errors.Is(err, ErrInvalidLifetime) ||
		errors.Is(err, ErrNilAuthorizer) ||
		errors.Is(err, opa.ErrNotAuthorized)
}

func (oneCa *OneCaType) SignCsrFile(ctx context.Context, csrFilename string, notAfter *time.Time, authorize SignAuthorizer) ([]byte, error) {
	proposedCertificate, pemBytes, err := signOneCsr(
		ctx,
		oneCa.logger,
		oneCa.caCertificate,
		oneCa.caPrivateKey,
		csrFilename,
		notAfter,
		oneCa.caConfig.ClockSkew,
		authorize,
	)
	if err != nil {
		return nil, err
	}

	if err := oneCa.gitCommitState(
		gitIssueCommitMessage(proposedCertificate),
		func() error {
			if err := writeIssuedCertificate(ctx, oneCa.logger, oneCa.issuedCertificatesDir, proposedCertificate, pemBytes); err != nil {
				return err
			}
			return os.Remove(csrFilename)
		},
		filepath.Join(gitCertificatesDirName, proposedCertificate.SerialNumber.String()+".crt.pem"),
	); err != nil {
		return nil, err
	}

	return pemBytes, nil
}

type RevokeAuthorizer func(ctx context.Context, issuedCertificate *x509.Certificate) error

// RevokeCertificate revokes the certificate the caller presented, on the
// strength of the certificate itself: its serial is read from it, so there is
// nothing for a client to name and therefore nothing to disagree with.
func (oneCa *OneCaType) RevokeCertificate(
	ctx context.Context,
	issuedCertificate *x509.Certificate,
	authorize RevokeAuthorizer,
) error {
	if authorize == nil {
		return ErrNilAuthorizer
	}
	if issuedCertificate == nil {
		return fmt.Errorf("%w: no certificate", ErrCertificateNotIssuedByThisCa)
	}
	if err := oneCa.certificateIsRevocable(issuedCertificate); err != nil {
		return err
	}

	return oneCa.revokeVerifiedCertificate(ctx, issuedCertificate, authorize)
}

// RevokeSerial revokes the certificate stored under a serial. The serial names
// the file to read, so it is a claim about which certificate is meant, and it
// is checked against the certificate that file actually holds: a copy of a
// certificate under a second name must not revoke the copy's name, and a
// policy that reasons about a serial must be reasoning about the serial that
// ends up in the CRL.
func (oneCa *OneCaType) RevokeSerial(ctx context.Context, crtSerial *big.Int, authorize RevokeAuthorizer) error {
	if authorize == nil {
		return ErrNilAuthorizer
	}
	if crtSerial == nil {
		return fmt.Errorf("%w: no serial", ErrUnknownSerial)
	}

	certificateFilename := filepath.Join(oneCa.issuedCertificatesDir, crtSerial.String()+".crt.pem")
	certificateContent, err := os.ReadFile(certificateFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrUnknownSerial, crtSerial.String())
		}
		return err
	}
	issuedCertificate, err := pemhelper.FromPemToCertificate(certificateContent)
	if err != nil {
		return err
	}
	if issuedCertificate.SerialNumber.Cmp(crtSerial) != 0 {
		return fmt.Errorf(
			"%w: %s holds a certificate with serial %s",
			ErrRevokeSerialMismatch,
			crtSerial.String(),
			issuedCertificate.SerialNumber.String(),
		)
	}
	if err := oneCa.certificateIsRevocable(issuedCertificate); err != nil {
		return err
	}

	return oneCa.revokeVerifiedCertificate(ctx, issuedCertificate, authorize)
}

// revokeVerifiedCertificate is the part both revoking paths share, reached only
// once the certificate is known to be this CA's and not the CA certificate
// itself. The serial that goes into the CRL is the one on the certificate, not
// the one the request named, so what the policy was asked about and what is
// published are the same thing.
func (oneCa *OneCaType) revokeVerifiedCertificate(
	ctx context.Context,
	issuedCertificate *x509.Certificate,
	authorize RevokeAuthorizer,
) error {
	if err := authorize(ctx, issuedCertificate); err != nil {
		return err
	}

	serial := issuedCertificate.SerialNumber
	// The revocation is worth publishing only while the certificate it names
	// can still be valid, and that window ends at the certificate's own
	// notAfter -- already no later than the CA's, because issuance caps it
	// there. Recorded now so the entry can leave the list on its own.
	revocationExpiresAt := issuedCertificate.NotAfter
	if oneCa.caCertificate.NotAfter.Before(revocationExpiresAt) {
		revocationExpiresAt = oneCa.caCertificate.NotAfter
	}
	if err := oneCa.gitCommitState(
		"revoke "+serial.String(),
		func() error {
			return updateCrl(
				oneCa.crlIndexFilename,
				oneCa.caFilenameCrl,
				oneCa.caConfig.CrlTtl,
				oneCa.caConfig.ClockSkew,
				oneCa.caCertificate,
				oneCa.caPrivateKey,
				[]oneRevocationRequest{{SerialNumber: serial, ExpiresAt: revocationExpiresAt}},
			)
		},
	); err != nil {
		return err
	}
	return nil
}

// GetCrlPem returns the CRL as PEM. A missing file is an error, not an empty
// body: a client that receives a zero-length CRL reads "nothing is revoked"
// from it, which is the wrong answer in the one direction that matters.
func (oneCa *OneCaType) GetCrlPem() ([]byte, error) {
	fileContent, _, err := oneCa.GetCrlPemAndModTime()
	return fileContent, err
}

// GetCrlPemAndModTime returns the CRL as PEM together with the modification
// time of the file it was read from. The content and the modification time
// come from the same open file, so the pair is coherent even while the
// background refresher replaces the CRL: the reader keeps the inode it opened,
// and the file the refresh writes is only visible to the next request.
func (oneCa *OneCaType) GetCrlPemAndModTime() ([]byte, time.Time, error) {
	crlFile, err := os.Open(oneCa.caFilenameCrl)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer crlFile.Close()

	fileContent, err := io.ReadAll(crlFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	fileInfo, err := crlFile.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	return fileContent, fileInfo.ModTime(), nil
}

func (oneCa *OneCaType) GetIssuerPem() ([]byte, error) {
	fileContent, err := pemhelper.ToPem(oneCa.caCertificate)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}
