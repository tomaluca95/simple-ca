//go:build unix

package caissuingprocess

import (
	"fmt"
	"os"
)

// ensurePrivateKeyFilePermissions refuses a key file that is group- or
// world-readable. New keys are written 0600; this catches a later chmod that
// would leave the CA private key exposed on a multi-user host.
func ensurePrivateKeyFilePermissions(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("private key file %s has mode %04o; refuse group/other access (want 0600)", filename, mode)
	}
	return nil
}
