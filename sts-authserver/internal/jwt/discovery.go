package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nais/sts/internal/jwa"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type issuerMetadata struct {
	Issuer             Issuer   `json:"issuer"`
	JWKSURI            string   `json:"jwks_uri"`
	IDTokenSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

func discoverRemoteKeySet(ctx context.Context, issuer Issuer, client *http.Client) (oidc.KeySet, []string, error) {
	base := strings.TrimSuffix(string(issuer), "/")
	metadata, found, err := fetchIssuerMetadata(ctx, client, base+oidc.DiscoveryEndpoint)
	if err == nil && !found {
		metadata, found, err = fetchIssuerMetadata(ctx, client, base+oidc.AuthorizationServerMetadataEndpoint)
	}
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, fmt.Errorf("no OIDC or OAuth metadata found for issuer %q", issuer)
	}
	if metadata.Issuer != issuer {
		return nil, nil, fmt.Errorf("configured issuer does not match issuer in discovery document: got %q, want %q", metadata.Issuer, issuer)
	}
	if metadata.JWKSURI == "" {
		return nil, nil, fmt.Errorf("discovery document has no jwks_uri")
	}

	algorithms := jwa.SupportedAlgorithms()
	if len(metadata.IDTokenSigningAlgs) > 0 {
		algorithms = jwa.FilterSupportedAlgorithms(metadata.IDTokenSigningAlgs)
		if len(algorithms) == 0 {
			return nil, nil, fmt.Errorf("issuer advertises no supported asymmetric signing algorithms: %q", metadata.IDTokenSigningAlgs)
		}
	}
	return rp.NewRemoteKeySet(client, metadata.JWKSURI), algorithms, nil
}

func fetchIssuerMetadata(ctx context.Context, client *http.Client, endpoint string) (issuerMetadata, bool, error) {
	var metadata issuerMetadata
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return metadata, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return metadata, false, fmt.Errorf("fetch metadata %q: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return metadata, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return metadata, false, fmt.Errorf("fetch metadata %q: unexpected status %d", endpoint, resp.StatusCode)
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&metadata); err != nil {
		return metadata, false, fmt.Errorf("decode metadata %q: %w", endpoint, err)
	}
	return metadata, true, nil
}
