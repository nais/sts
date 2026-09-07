//go:build integration_test

package integration

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/nais/sts/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestSts(t *testing.T) {
	oauthServer := startMockOAuthServer(t)
	sts, _ := startSts(t, oauthServer)

	t.Run("discovery", func(t *testing.T) {
		resp := get[oidc.DiscoveryConfiguration](t, sts.Endpoint(".well-known", "oauth-authorization-server"))
		assert.Equal(t, sts.Endpoint(), resp.Issuer)
		assert.Equal(t, sts.Endpoint("token"), resp.TokenEndpoint)
		assert.Equal(t, sts.Endpoint("jwks"), resp.JwksURI)

		assert.Equal(t, []oidc.GrantType{
			oidc.GrantTypeClientCredentials,
			oidc.GrantTypeTokenExchange,
		}, resp.GrantTypesSupported)

		assert.Equal(t, []oidc.AuthMethod{oidc.AuthMethodPrivateKeyJWT}, resp.TokenEndpointAuthMethodsSupported)
		assert.Equal(t, []string{"RS256"}, resp.TokenEndpointAuthSigningAlgValuesSupported)
	})

	t.Run("client credentials", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		form := clientCredentialsForm(clientAssertion, fixtures.Target)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Empty(t, resp.IssuedTokenType)
		assertTokenClaims(t, sts, resp, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, fixtures.ClientID, claims.Subject)
		})
	})

	t.Run("client credentials denies unauthorized scope", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		form := clientCredentialsForm(clientAssertion, "env1:namespace1:unauthorized")
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "authorization policy not found")
	})

	t.Run("client credentials denies unregistered client", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, "unregistered")
		form := clientCredentialsForm(clientAssertion, fixtures.Target)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "client not found")
	})

	t.Run("token exchange", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		subjectToken, subjectClaims := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Target)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenClaims(t, sts, resp, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, subjectClaims.Subject, claims.Subject)
		})
	})

	t.Run("token exchange with STS issued token", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		subjectToken, subjectClaims := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Target)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenClaims(t, sts, resp, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, subjectClaims.Subject, claims.Subject)
		})

		form = tokenExchangeForm(clientAssertion, resp.AccessToken, fixtures.Target)
		resp = stsToken[oauth.AccessTokenResponse](t, sts, form)
	
		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenClaims(t, sts, resp, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, subjectClaims.Subject, claims.Subject)
		})
	})

	t.Run("token exchange denies unauthorized audience", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		subjectToken, _ := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, "env1:namespace1:unauthorized")
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "authorization policy not found")
	})

	t.Run("token exchange denies unregistered client", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, "unregistered")
		subjectToken, _ := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Target)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "client not found")
	})

	t.Run("token exchange denies untrusted subject token issuer", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Environment, fixtures.Namespace, fixtures.ClientWorkload)
		subjectToken, _ := getSubjectToken(t, oauthServer, "untrusted")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Target)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "subject token is invalid")
	})
}

type claimAssertions func(claims *oauth.STSTokenClaims)

func assertTokenClaims(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, fn claimAssertions) {
	t.Helper()
	require.NotEmpty(t, response.AccessToken)

	wantExpiresIn := uint64(fixtures.TokenExpiry.Seconds())
	assert.GreaterOrEqual(t, response.ExpiresIn, wantExpiresIn-10)
	assert.LessOrEqual(t, response.ExpiresIn, wantExpiresIn)

	keys := get[jose.JSONWebKeySet](t, sts.Endpoint("jwks"))
	parsed, err := jwt.ParseSigned(response.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)

	matchingKeys := keys.Key(parsed.Headers[0].KeyID)
	require.Len(t, matchingKeys, 1)

	claims := new(oauth.STSTokenClaims)
	require.NoError(t, parsed.Claims(matchingKeys[0].Key, claims))

	assert.Equal(t, sts.Endpoint(), claims.Issuer)
	assert.Equal(t, oidc.Audience{fixtures.Target}, claims.Audience)
	assert.Equal(t, fixtures.ClientID, claims.ClientID)
	assert.Equal(t, oauth.Roles{fixtures.Role}, claims.ApplicationRoles)
	assert.NotEmpty(t, claims.JWTID)

	now := time.Now()
	assert.WithinDuration(t, now, claims.IssuedAt.AsTime(), 10*time.Second)
	assert.Equal(t, claims.IssuedAt.AsTime(), claims.NotBefore.AsTime())
	assert.Equal(t, fixtures.TokenExpiry, claims.Expiration.AsTime().Sub(claims.IssuedAt.AsTime()))

	fn(claims)
}

func clientCredentialsForm(clientAssertion, scope string) url.Values {
	return url.Values{
		"grant_type":            {string(oidc.GrantTypeClientCredentials)},
		"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
		"client_assertion":      {clientAssertion},
		"scope":                 {scope},
	}
}

func tokenExchangeForm(clientAssertion, subjectToken, audience string) url.Values {
	return url.Values{
		"grant_type":            {string(oidc.GrantTypeTokenExchange)},
		"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
		"client_assertion":      {clientAssertion},
		"audience":              {audience},
		"subject_token":         {subjectToken},
		"subject_token_type":    {string(oidc.JWTTokenType)},
		"requested_token_type":  {string(oidc.AccessTokenType)},
	}
}

func stsToken[T any](t testing.TB, sts testServer, form url.Values) *T {
	t.Helper()
	return post[T](t, sts.Endpoint("token"), form)
}

func getKubernetesToken(t testing.TB, oauthServer testServer, environment, namespace, workload string) string {
	t.Helper()

	resp := post[oidc.AccessTokenResponse](t, oauthServer.Endpoint(environment, "token"), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"ns":            {namespace},
		"workload":      {workload},
	})

	return resp.AccessToken
}

func getSubjectToken(t testing.TB, oauthServer testServer, issuer string) (string, *oauth.AccessTokenClaims) {
	t.Helper()

	redirectURI := "https://unused.example/callback"
	authorizeURL, err := url.Parse(oauthServer.Endpoint(issuer, "authorize"))
	require.NoError(t, err)

	authorizeURL.RawQuery = url.Values{
		"client_id":     {"default_client"},
		"scope":         {"openid somescope"},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
	}.Encode()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authorizeURL.String(), nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer ioconvenience.CloseWithLog(resp.Body, slog.Default())

	location, err := resp.Location()
	require.NoError(t, err)

	code := location.Query().Get("code")
	require.NotEmpty(t, code)

	token := post[oidc.AccessTokenResponse](t, oauthServer.Endpoint(issuer, "token"), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_secret": {"yolo"},
		"client_id":     {"default_client"},
		"redirect_uri":  {redirectURI},
	})

	verifier, err := oauth.NewTokenVerifier(t.Context(), nil, oauth.Issuer(oauthServer.Endpoint(issuer)))
	require.NoError(t, err)

	claims, err := verifier.Verify(t.Context(), token.AccessToken)
	require.NoError(t, err)

	return token.AccessToken, claims
}

func post[T any](t testing.TB, endpoint string, form url.Values) *T {
	t.Helper()

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, body)
	require.NoError(t, err, "creating request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ret := new(T)
	err = httphelper.HttpRequest(http.DefaultClient, req, ret)
	if oidcErr, ok := errors.AsType[*oidc.Error](err); ok {
		if response, ok := any(*oidcErr).(T); ok {
			return &response
		}
	}
	require.NoError(t, err, "HTTP request")
	return ret
}

func get[T any](t testing.TB, url string) *T {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err, "creating request")

	ret := new(T)
	err = httphelper.HttpRequest(http.DefaultClient, req, ret)
	require.NoError(t, err, "HTTP request")
	return ret
}
