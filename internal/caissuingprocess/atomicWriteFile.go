package caissuingprocess

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicWriteFile writes content to filename atomically: the content is written
// to a temporary file in the same directory, fsynced, and renamed over the
// target, then the directory entry is fsynced, so a crash never leaves a
// truncated file at the target path.
func atomicWriteFile(filename string, content []byte, mode os.FileMode) error {
	tmpFilename, err := prepareTempFile(filename, content, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFilename)

	if err := os.Rename(tmpFilename, filename); err != nil {
		return err
	}
	return syncDir(filepath.Dir(filename))
}

// atomicWriteFileExclusive is atomicWriteFile with the DATA-3 collision
// check: the fully written temporary file is hard-linked to the target, so the
// publish step itself fails with EEXIST when the target already exists and a
// concurrent writer can never observe a partially written file.
func atomicWriteFileExclusive(filename string, content []byte, mode os.FileMode) error {
	tmpFilename, err := prepareTempFile(filename, content, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFilename)

	if err := os.Link(tmpFilename, filename); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: %s", ErrCertificateFileExists, filename)
		}
		return err
	}
	return syncDir(filepath.Dir(filename))
}

func prepareTempFile(filename string, content []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp-*")
	if err != nil {
		return "", err
	}
	tmpFilename := tmpFile.Name()
	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpFilename)
	}

	if _, err := tmpFile.Write(content); err != nil {
		cleanup()
		return "", err
	}
	if err := tmpFile.Chmod(mode); err != nil {
		cleanup()
		return "", err
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFilename)
		return "", err
	}
	return tmpFilename, nil
}

// syncDir persists the directory entry updates (rename or hard link) for crash
// safety.
func syncDir(dir string) error {
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
