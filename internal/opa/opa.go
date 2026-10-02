package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout is the per-call budget for an OPA check when the caller did
// not configure one. OPA is asked on every sign, issue and revoke decision, so
// the default is tight: a slow policy is a bug until the operator raises the
// per-endpoint timeout in the config.
const DefaultTimeout = 500 * time.Millisecond

// maxResponseBytes caps how much of an OPA response is read. A misconfigured
// or compromised endpoint must not be able to force unbounded memory use.
const maxResponseBytes = 1 << 20

// TimeoutOrDefault returns the configured timeout, or DefaultTimeout when it
// is not set. A zero or negative value means "not set".
func TimeoutOrDefault(configured time.Duration) time.Duration {
	if configured <= 0 {
		return DefaultTimeout
	}
	return configured
}

// The client has no timeout of its own: every check carries its own budget as
// a context deadline, so a slow policy cannot borrow time from another
// endpoint's configured timeout. Redirects are refused so a compromised OPA
// URL cannot bounce the bearer token in the JSON body to a third party.
// Environment proxies (HTTP_PROXY / HTTPS_PROXY) are ignored for the same
// reason: the Authorization value travels in the OPA JSON body.
var httpClient = newHTTPClient()

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("opa redirects are not followed")
		},
	}
}

var ErrNotAuthorized = errors.New("not authorized")

var ErrUnavailable = errors.New("opa unavailable")

// Check asks the policy at url whether the request in input is authorized. The
// timeout bounds the whole call, so a policy that stops answering cannot hold a
// request forever; a non-positive timeout means DefaultTimeout.
func Check(
	ctx context.Context,
	url string,
	timeout time.Duration,
	input map[string]any,
) error {
	ctx, cancel := context.WithTimeout(ctx, TimeoutOrDefault(timeout))
	defer cancel()

	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return fmt.Errorf("%w: failed to marshal OPA input: %v", ErrUnavailable, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("%w: failed to create OPA request: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: failed to request OPA: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: OPA returned unexpected status: %s", ErrUnavailable, resp.Status)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("%w: failed to read OPA response: %v", ErrUnavailable, err)
	}
	if len(responseBody) > maxResponseBytes {
		return fmt.Errorf("%w: OPA response exceeds %d bytes", ErrUnavailable, maxResponseBytes)
	}

	var result struct {
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("%w: failed to decode OPA response: %v", ErrUnavailable, err)
	}

	if !result.Result {
		return ErrNotAuthorized
	}

	return nil
}
