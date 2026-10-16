package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Response[T any] struct {
	StatusCode int
	Body       T
}

type HTTPError struct {
	StatusCode int
	Body       string
}

// Error returns the HTTP status code and response body as an error message.
func (e HTTPError) Error() string {
	return fmt.Sprintf("HTTP request failed with status %d: %s", e.StatusCode, e.Body)
}

func newHTTPError(statusCode int, body string) HTTPError {
	return HTTPError{
		StatusCode: statusCode,
		Body:       body,
	}
}

func (r *RegistrationClient) sendRequest[R any](ctx context.Context, method string, path string, body any) (*Response[R], error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	endpoint := r.registerEndpoint
	if path != "" {
		endpoint += "/" + url.PathEscape(path)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	token, err := r.tokenCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode >= 400 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, newHTTPError(resp.StatusCode, fmt.Sprintf("failed to read response body: %v", err))
		}
		return nil, newHTTPError(resp.StatusCode, string(b))
	}
	var response R
	if resp.StatusCode != http.StatusNoContent {
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&response); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}

	return &Response[R]{
		StatusCode: resp.StatusCode,
		Body:       response,
	}, nil
}
