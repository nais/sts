package sts

import (
	"fmt"
	"os"
	"strings"
)

func getClientAuthToken(path string) (string, error) {
	// #nosec G304 -- The token file path comes from operator configuration, not request input.
	token, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("unable to read token from %s: %w", path, err)
	}
	accessToken := strings.TrimSpace(string(token))
	if accessToken == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return accessToken, nil
}
