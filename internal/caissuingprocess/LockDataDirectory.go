package caissuingprocess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrDataDirectoryLocked = errors.New("data directory is locked by another process")

// heldDataDirectoryLocks keeps a reference to the lock file of every lock this
// process holds. os.File closes its descriptor in a finalizer as soon as nothing
// references it any more, and closing the descriptor releases the lock: a
// caller that asks for a lock to last the whole process lifetime, like the HTTP
// server, would silently lose it at the first garbage collection unless the file
// is kept here. Keeping it here makes the lifetime of the lock the lifetime of
// the lock itself, and not the lifetime of a variable in the caller.
var heldDataDirectoryLocks = struct {
	sync.Mutex
	files map[string]*os.File
}{files: map[string]*os.File{}}

// rememberDataDirectoryLockFile keeps the lock file reachable for as long as the
// lock is held.
func rememberDataDirectoryLockFile(lockFilename string, lockFile *os.File) {
	heldDataDirectoryLocks.Lock()
	defer heldDataDirectoryLocks.Unlock()
	heldDataDirectoryLocks.files[lockFilename] = lockFile
}

// forgetDataDirectoryLockFile drops the reference kept by
// rememberDataDirectoryLockFile, so the lock file can be collected once it is
// closed.
func forgetDataDirectoryLockFile(lockFilename string) {
	heldDataDirectoryLocks.Lock()
	defer heldDataDirectoryLocks.Unlock()
	delete(heldDataDirectoryLocks.files, lockFilename)
}

// LockDataDirectory takes an exclusive lock on the data directory so only one
// simple-ca process (an HTTP server or a CLI run) works on it at a time. The
// lock is held by the open lock file: it is released by the returned function,
// or by the operating system when the process exits. A caller that wants the
// lock for the rest of the process may drop the returned function: the lock
// stays until the process ends either way.
func LockDataDirectory(dataDirectory string) (func() error, error) {
	if err := os.MkdirAll(dataDirectory, os.FileMode(0o711)); err != nil {
		return nil, fmt.Errorf("%s: %w", dataDirectory, err)
	}
	lockFilename := filepath.Join(dataDirectory, "simple-ca.lock")
	lockFile, err := os.OpenFile(lockFilename, os.O_RDWR|os.O_CREATE, os.FileMode(0o644))
	if err != nil {
		return nil, err
	}

	if err := lockFileExclusive(lockFile); err != nil {
		lockFile.Close()
		if !errors.Is(err, errLockWouldBlock) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s, lock file %s", ErrDataDirectoryLocked, dataDirectory, lockFilename)
	}

	// The lock is held from here on, so the file must not become garbage
	// before the lock is released.
	rememberDataDirectoryLockFile(lockFilename, lockFile)

	if err := lockFile.Truncate(0); err != nil {
		forgetDataDirectoryLockFile(lockFilename)
		unlockFileExclusive(lockFile)
		lockFile.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(lockFile, "%d\n", os.Getpid()); err != nil {
		forgetDataDirectoryLockFile(lockFilename)
		unlockFileExclusive(lockFile)
		lockFile.Close()
		return nil, err
	}

	return func() error {
		forgetDataDirectoryLockFile(lockFilename)
		if err := unlockFileExclusive(lockFile); err != nil {
			lockFile.Close()
			return err
		}
		return lockFile.Close()
	}, nil
}
