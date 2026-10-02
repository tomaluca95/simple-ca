package types_test

import (
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/types"
)

func TestHttpServerTimeoutOrDefault(t *testing.T) {
	if timeout := (types.HttpServerType{}).TimeoutOrDefault(); timeout != 5*time.Second {
		t.Errorf("expected the unset timeout to default to 5s, got %s", timeout)
	}
	if timeout := (types.HttpServerType{Timeout: 30 * time.Second}).TimeoutOrDefault(); timeout != 30*time.Second {
		t.Errorf("expected the configured 30s timeout, got %s", timeout)
	}
	if types.DefaultHttpServerTimeout != 5*time.Second {
		t.Errorf("expected the default timeout to be 5s, got %s", types.DefaultHttpServerTimeout)
	}
}
