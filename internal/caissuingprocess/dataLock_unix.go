//go:build unix

package caissuingprocess

import (
	"errors"
	"os"
	"syscall"
)

var errLockWouldBlock = errors.New("data directory lock would block")

func lockFileExclusive(lockFile *os.File) error {
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errLockWouldBlock
		}
		return err
	}
	return nil
}

func unlockFileExclusive(lockFile *os.File) error {
	return syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
}
