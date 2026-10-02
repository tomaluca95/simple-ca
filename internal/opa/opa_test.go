package opa_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/opa"
)

func newServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %q", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestCheckAllows(t *testing.T) {
	server := newServer(t, http.StatusOK, `{"result": true}`)
	if err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{"a": "b"}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestCheckSendsInputEnvelope(t *testing.T) {
	var lastBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(server.Close)

	if err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{
		"runtime":       "http",
		"authorization": "Bearer abc",
	}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}

	var got struct {
		Input map[string]any `json:"input"`
	}
	decoder := json.NewDecoder(strings.NewReader(lastBody))
	decoder.UseNumber()
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("OPA body must be the {\"input\": ...} envelope, got %q: %v", lastBody, err)
	}
	if got.Input["runtime"] != "http" {
		t.Fatalf("input.runtime mismatch, got %v", got.Input["runtime"])
	}
	if got.Input["authorization"] != "Bearer abc" {
		t.Fatalf("input.authorization mismatch, got %v", got.Input["authorization"])
	}
}

func TestCheckDeniesOnFalse(t *testing.T) {
	server := newServer(t, http.StatusOK, `{"result": false}`)
	err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got %v", err)
	}
}

func TestCheckDeniesOnUndefinedDecision(t *testing.T) {
	server := newServer(t, http.StatusOK, `{}`)
	err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized for undefined decision, got %v", err)
	}
}

func TestCheckUnavailableOnServerError(t *testing.T) {
	server := newServer(t, http.StatusInternalServerError, `boom`)
	err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestCheckUnavailableOnMalformedResponse(t *testing.T) {
	server := newServer(t, http.StatusOK, `not-json`)
	err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestCheckUnavailableWhenUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	err := opa.Check(context.Background(), url, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestTimeoutOrDefault(t *testing.T) {
	if got := opa.TimeoutOrDefault(0); got != opa.DefaultTimeout {
		t.Fatalf("zero must mean the default, got %s", got)
	}
	if got := opa.TimeoutOrDefault(-time.Second); got != opa.DefaultTimeout {
		t.Fatalf("a negative value must mean the default, got %s", got)
	}
	configured := 3 * time.Second
	if got := opa.TimeoutOrDefault(configured); got != configured {
		t.Fatalf("expected the configured %s, got %s", configured, got)
	}
}

func TestCheckTimesOutSlowPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(server.Close)

	start := time.Now()
	err := opa.Check(context.Background(), server.URL, 50*time.Millisecond, map[string]any{})
	elapsed := time.Since(start)
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("a slow policy must be cut off as unavailable, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("expected the budget to cut the call off, took %s", elapsed)
	}
}

func TestCheckHonorsBudgetForSlowButViablePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(server.Close)

	if err := opa.Check(context.Background(), server.URL, 2*time.Second, map[string]any{}); err != nil {
		t.Fatalf("a policy within its budget must succeed, got %v", err)
	}
}

func TestCheckUsesDefaultTimeoutWhenUnset(t *testing.T) {
	// The policy sleeps 100ms, well within the 500ms default: passing zero must
	// not cancel the call immediately, which is what a zero deadline would do.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	t.Cleanup(server.Close)

	if err := opa.Check(context.Background(), server.URL, 0, map[string]any{}); err != nil {
		t.Fatalf("expected the default budget to cover the policy, got %v", err)
	}
}

func TestCheckRefusesRedirect(t *testing.T) {
	final := newServer(t, http.StatusOK, `{"result": true}`)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	err := opa.Check(context.Background(), redirector.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("a redirect must be unavailable, got %v", err)
	}
}

func TestCheckRefusesOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Just over the 1MiB cap.
		w.Write(bytes.Repeat([]byte("a"), (1<<20)+2))
	}))
	t.Cleanup(server.Close)

	err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{})
	if !errors.Is(err, opa.ErrUnavailable) {
		t.Fatalf("an oversized response must be unavailable, got %v", err)
	}
}

func TestCheckIgnoresHTTPProxy(t *testing.T) {
	server := newServer(t, http.StatusOK, `{"result": true}`)
	// A dead proxy: DefaultTransport would fail the call if it honored these.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	if err := opa.Check(context.Background(), server.URL, opa.DefaultTimeout, map[string]any{
		"authorization": "Bearer must-not-reach-a-proxy",
	}); err != nil {
		t.Fatalf("OPA must talk directly even when HTTP_PROXY is set, got %v", err)
	}
}
