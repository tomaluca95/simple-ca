//go:build unix

package caissuingprocess_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A spool entry that is not a regular file is skipped before it is read. A FIFO
// in the drop box would otherwise block the read forever, taking the whole CLI
// run with it and logging nothing about what it was waiting on.
func TestRsaCsrSpoolSkipsANonRegularEntry(t *testing.T) {
	logger, logOutput := capturingLogger()
	oneCa, dataDirectory := loadCaWithLogger(t, logger)

	fifoFilename := filepath.Join(dataDirectory, "test_ca_1", "data", "csr", "hang.csr.pem")
	if err := syscall.Mkfifo(fifoFilename, 0o644); err != nil {
		t.Fatal(err)
	}

	// Run with a leash, so a regression fails in ten seconds rather than
	// hanging the suite on a read that never returns.
	done := make(chan error, 1)
	go func() {
		done <- oneCa.IssueAllCsrInQueue(context.Background(), allowSign)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a non-regular entry must be skipped, not fail the queue: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("IssueAllCsrInQueue did not return: a non-regular spool entry blocked the read")
	}

	if !strings.Contains(logOutput.String(), "not a regular file") {
		t.Errorf("expected the non-regular entry to be reported, got:\n%s", logOutput.String())
	}
	if _, err := os.Stat(fifoFilename); err != nil {
		t.Errorf("a skipped entry must be left where it is: %v", err)
	}
}
