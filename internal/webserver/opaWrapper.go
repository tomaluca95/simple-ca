package webserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func (httpWrapper *httpWrapperType) opaWrapper(
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

	resp, err := http.DefaultClient.Post(opaUrl, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to request OPA: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode OPA response: %w", err)
	}

	if !result.Result {
		return fmt.Errorf("OPA denied the request")
	}

	return nil
}
