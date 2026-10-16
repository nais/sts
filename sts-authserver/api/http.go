package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTPError reports an unexpected HTTP status and preserves the response body.
type HTTPError struct {
	StatusCode int
	// ExpectedStatusCode is the status required by the operation, or zero if unknown.
	ExpectedStatusCode int
	Body               string
}

// Error returns the actual and expected HTTP status codes and response body.
func (e HTTPError) Error() string {
	if e.ExpectedStatusCode != 0 && e.StatusCode != e.ExpectedStatusCode {
		return fmt.Sprintf("HTTP request failed with unexpected status: got %d, want %d: %s", e.StatusCode, e.ExpectedStatusCode, e.Body)
	}
	return fmt.Sprintf("HTTP request failed with status %d: %s", e.StatusCode, e.Body)
}

func newHTTPError(statusCode, expectedStatusCode int, body string) HTTPError {
	return HTTPError{
		StatusCode:         statusCode,
		ExpectedStatusCode: expectedStatusCode,
		Body:               body,
	}
}

type requester struct {
	httpClient *http.Client
}

func (r *requester) Do[R any](ctx context.Context, url string, method string, body any, expectedStatus int, tokenCallback AuthTokenCallback) (*R, error) {
	headers := map[string]string{}
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
		headers["Content-Type"] = "application/json"
	}

	if tokenCallback != nil {
		token, err := tokenCallback(ctx)
		if err != nil {
			return nil, fmt.Errorf("get token: %w", err)
		}
		headers["Authorization"] = "Bearer " + token
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	return decodeResponse[R](resp, expectedStatus)
}

func decodeResponse[R any](resp *http.Response, expectedStatus int) (*R, error) {
	if resp.StatusCode != expectedStatus {
		body, err := io.ReadAll(resp.Body)
		httpErr := newHTTPError(resp.StatusCode, expectedStatus, string(body))
		if err != nil {
			return nil, fmt.Errorf("read response body: %w; %w", err, httpErr)
		}
		return nil, httpErr
	}

	var response R
	if resp.StatusCode != http.StatusNoContent {
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&response); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}
	return &response, nil
}
