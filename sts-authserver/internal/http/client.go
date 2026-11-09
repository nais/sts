package http

import (
	"fmt"
	nethttp "net/http"
	"time"
)

// NewClient rejects redirects to require explicit final URLs for discovery and
// JWKS requests.
func NewClient() *nethttp.Client {
	return &nethttp.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *nethttp.Request, _ []*nethttp.Request) error {
			return fmt.Errorf("redirect to %q is not allowed", req.URL)
		},
	}
}
