package mainprocess

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/opa"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func RunWithConfigFileData(
	ctx context.Context,
	logger types.Logger,
	configFile types.ConfigFileType,
) error {
	if err := configFile.Validate(); err != nil {
		return err
	}

	unlockDataDirectory, err := caissuingprocess.LockDataDirectory(configFile.DataDirectory)
	if err != nil {
		return err
	}
	defer func() {
		if err := unlockDataDirectory(); err != nil {
			logger.ErrorContext(ctx, "failed to release the data directory lock", "err", err)
		}
	}()

	allErrors := []error{}
	for caId, caConfig := range configFile.AllCaConfigs {
		oneCa, err := caissuingprocess.LoadOneCa(
			ctx,
			logger,
			caId,
			configFile.DataDirectory,
			caConfig,
		)
		if err != nil {
			allErrors = append(allErrors,
				fmt.Errorf("error in %s: %w", caId, err),
			)
			continue
		}

		opaUrlSign := *caConfig.OpaUrlSign
		opaUrlIssueCa := *caConfig.OpaUrlIssueCa
		opaTimeoutSign := caConfig.OpaTimeoutSign
		opaTimeoutIssueCa := caConfig.OpaTimeoutIssueCa
		authorize := func(ctx context.Context, proposedCertificate *x509.Certificate) error {
			opaUrl := opaUrlSign
			opaTimeout := opaTimeoutSign
			if proposedCertificate.IsCA {
				opaUrl = opaUrlIssueCa
				opaTimeout = opaTimeoutIssueCa
			}
			return opa.Check(ctx, opaUrl, opaTimeout, map[string]any{
				"runtime":              "cli",
				"authorization":        "",
				"proposed_certificate": caissuingprocess.NewCertificateView(proposedCertificate),
			})
		}

		if err := oneCa.IssueAllCsrInQueue(ctx, authorize); err != nil {
			allErrors = append(allErrors,
				fmt.Errorf("error in %s: %w", caId, err),
			)
		}

		if err := oneCa.UpdateCrl(); err != nil {
			allErrors = append(allErrors,
				fmt.Errorf("error in %s: %w", caId, err),
			)
		}
	}
	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}
	return nil
}
