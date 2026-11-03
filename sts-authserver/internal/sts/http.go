package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

const shutdownTimeout = 5 * time.Second

func shutdown(server *http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down server: %w", err)
	}
	return nil
}

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

// TODO: is this only necessary for local k3d? perhaps also for service discovery or in-cluster?
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
		MinVersion: tls.VersionTLS12, // TODO: why tls 1.2? why not 1.3? why hard code at all?
		RootCAs:    roots,
	}
	client.Transport = transport
	return client, nil
}
