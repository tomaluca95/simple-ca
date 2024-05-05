package mainprocess

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/types"
)

func RunWithConfigFileData(
	ctx context.Context,
	configFile types.ConfigFileType,
) error {
	if err := os.MkdirAll(configFile.DataDirectory, os.FileMode(0o711)); err != nil {
		return err
	}
	allErrors := []error{}
	for caId, caConfig := range configFile.AllCaConfigs {
		oneCa, err := caissuingprocess.LoadOneCa(
			ctx,
			caId,
			configFile.DataDirectory,
			caConfig,
		)
		if err != nil {
			allErrors = append(allErrors,
				fmt.Errorf("error in %s: %w", caId, err),
			)
		} else {
			if err := oneCa.IssueAllCsrInQueue(); err != nil {
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
	}
	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}
	return nil
}
