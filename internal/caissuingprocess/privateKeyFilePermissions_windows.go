//go:build windows

package caissuingprocess

// ensurePrivateKeyFilePermissions is a no-op on Windows: unix mode bits are
// not a reliable ACL signal there, and the data-directory flock already
// serializes writers for this process.
func ensurePrivateKeyFilePermissions(filename string) error {
	return nil
}
