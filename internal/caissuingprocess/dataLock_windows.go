//go:build windows

package caissuingprocess

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errLockWouldBlock = errors.New("data directory lock would block")

func lockFileExclusive(lockFile *os.File) error {
	if err := windows.LockFileEx(
		windows.Handle(lockFile.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		new(windows.Overlapped),
	); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return errLockWouldBlock
		}
		return err
	}
	return nil
}

func unlockFileExclusive(lockFile *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(lockFile.Fd()),
		0,
		1,
		0,
		new(windows.Overlapped),
	)
}
