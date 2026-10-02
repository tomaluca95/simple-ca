//go:build unix

package caissuingprocess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestRsaPrivateKeyRefusesWorldReadableMode(t *testing.T) {
	logger := &types.StdLogger{}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key.pem")

	if _, err := getRsaPrivateKeyOrCreateNew(logger, keyPath, 2048); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := getRsaPrivateKeyOrCreateNew(logger, keyPath, 2048)
	if err == nil {
		t.Fatal("expected refusal of a world-readable private key")
	}
	if !strings.Contains(err.Error(), "group/other access") {
		t.Fatalf("unexpected error: %v", err)
	}
}
