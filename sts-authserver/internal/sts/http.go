package sts

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	internalhttp "github.com/nais/sts/internal/http"
)

func serve(server *http.Server) error {
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func httpServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}
}

type httpClientOption func(*http.Client) error

// httpClient returns the client used for upstream OAuth and JWKS requests.
func httpClient(opts ...httpClientOption) (*http.Client, error) {
	client := internalhttp.NewClient()

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// withAdditionalCAFile adds the PEM certificates in path to the system roots;
// verification stays enabled. It lets a host-run authserver trust the local
// k3d CA, since macOS Go ignores SSL_CERT_FILE.
func withAdditionalCAFile(path string) httpClientOption {
	return func(client *http.Client) error {
		// #nosec G304 -- path is an operator-controlled config path, not request input.
		caPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read additional CA file: %w", err)
		}

		roots, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("load system certificate pool: %w", err)
		}

		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("additional CA file %q contains no valid PEM certificates", path)
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		}

		client.Transport = transport
		return nil
	}
}
