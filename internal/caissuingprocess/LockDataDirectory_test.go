package caissuingprocess_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
)

func TestLockDataDirectory(t *testing.T) {
	dataDirectory := t.TempDir()

	unlockFirst, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}

	// A second lock on the same directory, as a second process would take it,
	// fails with a clear error.
	_, err = caissuingprocess.LockDataDirectory(dataDirectory)
	if !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected ErrDataDirectoryLocked, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "data directory is locked by another process") {
		t.Errorf("expected a clear in-use message, got %v", err)
	}

	if err := unlockFirst(); err != nil {
		t.Fatal(err)
	}

	unlockSecond, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockSecond()

	lockFileContent, err := os.ReadFile(filepath.Join(dataDirectory, "simple-ca.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(lockFileContent)); got != strconv.Itoa(os.Getpid()) {
		t.Errorf("expected the lock file to contain pid %d, got %q", os.Getpid(), got)
	}
}

func TestLockDataDirectoryOutlivesGarbageCollection(t *testing.T) {
	dataDirectory := t.TempDir()

	// The returned unlock is deliberately dropped: a caller that wants the lock
	// for the rest of the process, like the HTTP server, has nothing to hold on
	// to. The lock must survive on its own.
	if _, err := caissuingprocess.LockDataDirectory(dataDirectory); err != nil {
		t.Fatal(err)
	}

	// Two collections, because the finalizer of the lock file runs on the one
	// after the file itself becomes unreachable, and the short sleep gives it
	// the chance to run before the lock is probed.
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	if _, err := caissuingprocess.LockDataDirectory(dataDirectory); !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected the dropped lock to still be held, got %v", err)
	}
}

func TestUnlockDataDirectoryReleasesAfterGarbageCollection(t *testing.T) {
	dataDirectory := t.TempDir()

	unlock, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}

	// Unlocking explicitly releases the lock, so it can be taken again, and the
	// lock taken after that one is held like any other.
	unlockSecond, err := caissuingprocess.LockDataDirectory(dataDirectory)
	if err != nil {
		t.Fatalf("expected the lock to be released, got %v", err)
	}
	defer unlockSecond()

	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	if _, err := caissuingprocess.LockDataDirectory(dataDirectory); !errors.Is(err, caissuingprocess.ErrDataDirectoryLocked) {
		t.Errorf("expected the lock to be held, got %v", err)
	}
}
