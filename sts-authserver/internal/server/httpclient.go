package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// newHTTPClient returns the client used for upstream OAuth and JWKS requests.
// A nonempty additionalCAFile adds its PEM certificates to the system roots;
// verification stays enabled.
func newHTTPClient(additionalCAFile string) (*http.Client, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirect to %q is not allowed", req.URL)
		},
	}
	if additionalCAFile == "" {
		return client, nil
	}

	// #nosec G304 -- additionalCAFile is an operator-controlled config path, not request input.
	caPEM, err := os.ReadFile(additionalCAFile)
	if err != nil {
		return nil, fmt.Errorf("read additional CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", err)
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("additional CA file %q contains no valid PEM certificates", additionalCAFile)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	client.Transport = transport
	return client, nil
}
