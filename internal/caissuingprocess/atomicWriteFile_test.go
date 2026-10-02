package caissuingprocess

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "crl.pem")
	if err := atomicWriteFile(filename, []byte("first"), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first" {
		t.Errorf("expected first content, got %q", content)
	}

	// Overwriting replaces the content, unlike the exclusive variant.
	if err := atomicWriteFile(filename, []byte("second"), os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "second" {
		t.Errorf("expected second content, got %q", content)
	}

	fileInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o644 {
		t.Errorf("expected mode 0644, got %v", fileInfo.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected no leftover temporary files, got %v", entries)
	}
}
