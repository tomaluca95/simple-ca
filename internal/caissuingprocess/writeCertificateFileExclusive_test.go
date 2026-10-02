package caissuingprocess

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteCertificateFileExclusive(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "1.crt.pem")
	if err := writeCertificateFileExclusive(filename, []byte("first")); err != nil {
		t.Fatal(err)
	}
	err := writeCertificateFileExclusive(filename, []byte("second"))
	if !errors.Is(err, ErrCertificateFileExists) {
		t.Errorf("expected ErrCertificateFileExists, got %v", err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first" {
		t.Errorf("first write must not be overwritten, got %q", content)
	}
}

func TestWriteCertificateFileExclusiveConcurrent(t *testing.T) {
	const writers = 8
	filename := filepath.Join(t.TempDir(), "1.crt.pem")

	results := make(chan error, writers)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for i := 0; i < writers; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			results <- writeCertificateFileExclusive(filename, []byte("content"))
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	collisions := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrCertificateFileExists) {
			t.Errorf("unexpected error: %v", err)
			continue
		}
		collisions++
	}
	if successes != 1 {
		t.Errorf("exactly one writer must win, got %d", successes)
	}
	if collisions != writers-1 {
		t.Errorf("all other writers must see the collision, got %d", collisions)
	}
}
