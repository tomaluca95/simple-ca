package webserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var opaHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

var ErrNotAuthorized = fmt.Errorf("not authorized")

func (httpWrapper *httpWrapperType) opaWrapper(
	ctx context.Context,
	opaUrl string,
	data map[string]string,
) error {
	input := map[string]any{
		"input": data,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal OPA input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opaUrl, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := opaHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA returned unexpected status: %s", resp.Status)
	}

	var result struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode OPA response: %w", err)
	}

	if !result.Result {
		return ErrNotAuthorized
	}

	return nil
}
