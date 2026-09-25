//go:build integration_test

package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/crypto"
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
		assert.Empty(t, resp.IDTokenSigningAlgValuesSupported)
	})

	t.Run("registration", func(t *testing.T) {
		registratorToken := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, "registrator1")
		otherRegistratorToken := getKubernetesToken(t, oauthServer, "env2", fixtures.Client1.Namespace, "registrator2")
		statement := registration.SoftwareStatement{
			ClientId: "env1:namespace1:registered-workload",
			Workload: registration.Workload{
				Environment: fixtures.Client1.Environment,
				Issuer:      oauthServer.Endpoint(fixtures.Client1.Environment),
				Namespace:   fixtures.Client1.Namespace,
				Name:        "registered-workload",
			},
			AuthorizationPolicies: []registration.AuthorizationPolicy{
				{
					Consumer: fixtures.Client2.ID,
					Roles:    []string{fixtures.Role},
				},
			},
		}
		signed := signSoftwareStatement(t, statement)

		// These subtests share one registration from creation through deletion.
		t.Run("accepts valid registration", func(t *testing.T) {
			request := registration.ClientRegistration{
				SoftwareStatement: signed,
			}
			status, response := postRegistration[registration.ClientRegistrationResponse](t, sts, registratorToken, request)
			require.Equal(t, http.StatusOK, status, response)
			assert.Equal(t, statement.ClientId, response.ClientID)
			assert.Equal(t, signed, response.SoftwareStatement)

			// Verify that both the client and its authorization policy were persisted.
			clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, statement.Workload.Name)
			token := stsToken[oauth.AccessTokenResponse](t, sts, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))
			require.NotEmpty(t, token.AccessToken)
		})

		t.Run("replaces registration", func(t *testing.T) {
			status, response := postRegistration[registration.ClientRegistrationResponse](t, sts, registratorToken, registration.ClientRegistration{
				SoftwareStatement: signed,
			})
			require.Equal(t, http.StatusOK, status, response)
			assert.Equal(t, statement.ClientId, response.ClientID)
			assert.Equal(t, signed, response.SoftwareStatement)
		})

		t.Run("registers another client", func(t *testing.T) {
			another := statement
			another.ClientId = "env1:namespace1:another-workload"
			another.Workload.Name = "another-workload"
			another.AuthorizationPolicies = []registration.AuthorizationPolicy{
				{
					Consumer: fixtures.Client2.ID,
					Roles:    []string{fixtures.Role},
				},
			}

			status, response := postRegistration[registration.ClientRegistrationResponse](t, sts, registratorToken, registration.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, another),
			})
			require.Equal(t, http.StatusOK, status, response)

			clientAssertion := getKubernetesToken(t, oauthServer, another.Workload.Environment, another.Workload.Namespace, another.Workload.Name)
			token := stsToken[oauth.AccessTokenResponse](t, sts, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))
			require.NotEmpty(t, token.AccessToken)

			status, _ = deleteRegistration[oidc.Error](t, sts, registratorToken, another.ClientId)
			require.Equal(t, http.StatusNoContent, status)
		})

		t.Run("rejects registration for unauthorized workload issuer", func(t *testing.T) {
			unauthorized := statement
			unauthorized.AuthorizationPolicies = slices.Clone(statement.AuthorizationPolicies)
			unauthorized.ClientId = "env2:namespace1:unauthorized-workload"
			unauthorized.Workload.Environment = "env2"
			unauthorized.Workload.Issuer = oauthServer.Endpoint("env2")
			status, response := postRegistration[oidc.Error](t, sts, registratorToken, registration.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, unauthorized),
			})
			require.Equal(t, http.StatusForbidden, status, response)
			assert.Contains(t, response.Description, "not authorized")
		})

		t.Run("rejects workload identity collision", func(t *testing.T) {
			collision := statement
			collision.AuthorizationPolicies = slices.Clone(statement.AuthorizationPolicies)
			collision.ClientId = "env1:namespace1:other-client"
			status, response := postRegistration[oidc.Error](t, sts, registratorToken, registration.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, collision),
			})
			require.Equal(t, http.StatusConflict, status, response)
			assert.Equal(t, oidc.InvalidClient, response.ErrorType)
		})

		t.Run("rejects replacement without authority over existing issuer", func(t *testing.T) {
			replacement := statement
			replacement.Workload.Environment = "env2"
			replacement.Workload.Issuer = oauthServer.Endpoint("env2")
			status, response := postRegistration[oidc.Error](t, sts, otherRegistratorToken, registration.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, replacement),
			})
			require.Equal(t, http.StatusForbidden, status, response)
			assert.Contains(t, response.Description, "not authorized")
		})

		t.Run("does not delete registration outside issuer authority", func(t *testing.T) {
			status, response := deleteRegistration[oidc.Error](t, sts, otherRegistratorToken, statement.ClientId)
			require.Equal(t, http.StatusForbidden, status, response)
			assert.Equal(t, oidc.InvalidClient, response.ErrorType)

			clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, statement.Workload.Name)
			token := stsToken[oauth.AccessTokenResponse](t, sts, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))
			require.NotEmpty(t, token.AccessToken)
		})

		t.Run("deletes missing registration", func(t *testing.T) {
			status, _ := deleteRegistration[oidc.Error](t, sts, registratorToken, "env1:namespace1:missing")
			require.Equal(t, http.StatusNoContent, status)
		})

		t.Run("rejects invalid software statement signature", func(t *testing.T) {
			request := registration.ClientRegistration{
				SoftwareStatement: tamperJWTSignature(t, signed),
			}
			status, response := postRegistration[oidc.Error](t, sts, registratorToken, request)
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Contains(t, response.Description, "invalid software statement")
		})

		t.Run("rejects unauthorized registrator", func(t *testing.T) {
			unauthorizedToken := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, "not-a-registrator")
			request := registration.ClientRegistration{
				SoftwareStatement: signed,
			}
			status, response := postRegistration[oidc.Error](t, sts, unauthorizedToken, request)
			require.Equal(t, http.StatusUnauthorized, status, response)
			assert.Contains(t, response.Description, "unauthorized")
		})

		t.Run("rejects malformed request", func(t *testing.T) {
			status, response := postRegistration[oidc.Error](t, sts, registratorToken, map[string]any{
				"software_statement": signed,
				"unknown":            true,
			})
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Contains(t, response.Description, "invalid request body")
		})

		t.Run("rejects unsupported content type", func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sts.Endpoint("v1", "registration", "client"), strings.NewReader("{}"))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("Authorization", "Bearer "+registratorToken)

			status, response := registrationRequest[oidc.Error](t, req)
			require.Equal(t, http.StatusUnsupportedMediaType, status, response)
			assert.Contains(t, response.Description, "content type must be application/json")
		})

		t.Run("rejects oversized request", func(t *testing.T) {
			status, response := postRegistration[oidc.Error](t, sts, registratorToken, registration.ClientRegistration{
				SoftwareStatement: strings.Repeat("x", 65<<10),
			})
			require.Equal(t, http.StatusRequestEntityTooLarge, status, response)
			assert.Contains(t, response.Description, "request body too large")
		})

		t.Run("rejects missing bearer token", func(t *testing.T) {
			status, response := postRegistration[oidc.Error](t, sts, "", registration.ClientRegistration{
				SoftwareStatement: signed,
			})
			require.Equal(t, http.StatusUnauthorized, status, response)
			assert.Equal(t, "unauthorized", response.Description)
		})

		for _, id := range []string{
			"1client",
			"Client",
			"client-",
			"client:",
			"client_name",
			"client.name",
		} {
			t.Run("rejects invalid client ID "+id, func(t *testing.T) {
				status, response := deleteRegistration[oidc.Error](t, sts, registratorToken, id)
				require.Equal(t, http.StatusBadRequest, status, response)
				assert.Contains(t, response.Description, "invalid client ID")
			})
		}

		t.Run("deletes registration with valid client ID", func(t *testing.T) {
			status, _ := deleteRegistration[oidc.Error](t, sts, registratorToken, statement.ClientId)
			require.Equal(t, http.StatusNoContent, status)

			clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, statement.Workload.Name)
			resp := stsToken[oidc.Error](t, sts, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))
			assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
			assert.Contains(t, resp.Description, "client not found")
		})
	})

	t.Run("client credentials", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		form := clientCredentialsForm(clientAssertion, fixtures.Client2.ID)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Empty(t, resp.IssuedTokenType)
		assertTokenClaims(t, sts, resp, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, fixtures.Client1.ID, claims.Subject)
			assert.Equal(t, oidc.GrantTypeClientCredentials, claims.GrantType)
			assert.Nil(t, claims.Actor)
		})
	})

	t.Run("client credentials denies unauthorized scope", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		form := clientCredentialsForm(clientAssertion, "env1:namespace1:unauthorized")
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "authorization policy not found")
	})

	t.Run("client credentials denies unregistered client", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, "unregistered")
		form := clientCredentialsForm(clientAssertion, fixtures.Client2.ID)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "client not found")
	})

	t.Run("token exchange", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		subjectToken, subjectClaims := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenExchangeClaims(t, sts, resp, subjectClaims)
		assertTokenActor(t, sts, resp, fixtures.Client1.ID, nil)
	})

	t.Run("token exchange with STS issued token", func(t *testing.T) {
		client1Assertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		subjectToken, subjectClaims := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(client1Assertion, subjectToken, fixtures.Client2.ID)
		resp := stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenExchangeClaims(t, sts, resp, subjectClaims)
		firstActor := assertTokenActor(t, sts, resp, fixtures.Client1.ID, nil)

		client2Assertion := getKubernetesToken(t, oauthServer, fixtures.Client2.Environment, fixtures.Client2.Namespace, fixtures.Client2.Workload)
		form = tokenExchangeForm(client2Assertion, resp.AccessToken, fixtures.Client3.ID)
		resp = stsToken[oauth.AccessTokenResponse](t, sts, form)

		assert.Equal(t, oidc.BearerToken, resp.TokenType)
		assert.Equal(t, oidc.AccessTokenType, resp.IssuedTokenType)
		assertTokenExchangeClaimsForTarget(t, sts, resp, subjectClaims, fixtures.Client3.ID, fixtures.Client2.ID)
		assertTokenActorForTarget(t, sts, resp, fixtures.Client3.ID, fixtures.Client2.ID, fixtures.Client2.ID, firstActor)
	})

	t.Run("token exchange denies STS client credentials token", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		clientCredentialsToken := stsToken[oauth.AccessTokenResponse](t, sts, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))

		resp := stsToken[oidc.Error](t, sts, tokenExchangeForm(clientAssertion, clientCredentialsToken.AccessToken, fixtures.Client2.ID))

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "grant_type claim is invalid")
	})

	t.Run("token exchange denies unauthorized audience", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		subjectToken, _ := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, "env1:namespace1:unauthorized")
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "authorization policy not found")
	})

	t.Run("token exchange denies unregistered client", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, "unregistered")
		subjectToken, _ := getSubjectToken(t, oauthServer, "subject1")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "client not found")
	})

	t.Run("token exchange denies untrusted subject token issuer", func(t *testing.T) {
		clientAssertion := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, fixtures.Client1.Workload)
		subjectToken, _ := getSubjectToken(t, oauthServer, "untrusted")
		form := tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID)
		resp := stsToken[oidc.Error](t, sts, form)

		assert.Equal(t, oidc.InvalidClient, resp.ErrorType)
		assert.Contains(t, resp.Description, "subject token is invalid")
	})
}

func assertTokenActor(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, clientID string, previous *oauth.ActorClaims) *oauth.ActorClaims {
	return assertTokenActorForTarget(t, sts, response, fixtures.Client2.ID, fixtures.Client1.ID, clientID, previous)
}

func assertTokenActorForTarget(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, target, tokenClientID, actorClientID string, previous *oauth.ActorClaims) *oauth.ActorClaims {
	t.Helper()
	var actor *oauth.ActorClaims
	assertTokenClaimsForTarget(t, sts, response, target, tokenClientID, func(claims *oauth.STSTokenClaims) {
		actor = claims.Actor
		require.NotNil(t, actor)
		assert.Equal(t, sts.Endpoint(), actor.Issuer)
		assert.Equal(t, actorClientID, actor.ClientID)
		assert.Equal(t, previous, actor.Actor)
	})
	return actor
}

type claimAssertions func(claims *oauth.STSTokenClaims)

func assertTokenExchangeClaims(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, subjectClaims *oauth.AccessTokenClaims) {
	assertTokenExchangeClaimsForTarget(t, sts, response, subjectClaims, fixtures.Client2.ID, fixtures.Client1.ID)
}

func assertTokenExchangeClaimsForTarget(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, subjectClaims *oauth.AccessTokenClaims, target, clientID string) {
	t.Helper()

	// Parse the issued token as typed STS claims and as a complete raw claim map.
	var stsClaims *oauth.STSTokenClaims
	issuedClaims := assertTokenClaimsForTarget(t, sts, response, target, clientID, func(claims *oauth.STSTokenClaims) {
		stsClaims = claims
		assert.Equal(t, subjectClaims.Subject, claims.Subject)
		assert.Equal(t, oidc.GrantTypeTokenExchange, claims.GrantType)
		assert.NotEqual(t, subjectClaims.Issuer, claims.Issuer)
		assert.NotEqual(t, subjectClaims.Audience, claims.Audience)
		assert.NotEqual(t, subjectClaims.ClientID, claims.ClientID)
	})

	// Preserve original subject token claims
	expectedClaims := maps.Clone(subjectClaims.Claims)

	// Marshal the typed STS claims to their JWT claim names and values.
	data, err := json.Marshal(stsClaims)
	require.NoError(t, err)

	// Unmarshal into the clone to overwrite STS-owned claims and retain all other subject claims.
	require.NoError(t, json.Unmarshal(data, &expectedClaims))

	// Assert that the issued token contains exactly the expected merged claims.
	assert.Equal(t, expectedClaims, issuedClaims.Claims)
}

func assertTokenClaims(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, fn claimAssertions) *oauth.AccessTokenClaims {
	return assertTokenClaimsForTarget(t, sts, response, fixtures.Client2.ID, fixtures.Client1.ID, fn)
}

func assertTokenClaimsForTarget(t *testing.T, sts testServer, response *oauth.AccessTokenResponse, target, clientID string, fn claimAssertions) *oauth.AccessTokenClaims {
	t.Helper()
	require.NotEmpty(t, response.AccessToken)

	wantExpiresIn := uint64(fixtures.TokenExpiry.Seconds())
	assert.GreaterOrEqual(t, response.ExpiresIn, wantExpiresIn-10)
	assert.LessOrEqual(t, response.ExpiresIn, wantExpiresIn)

	tokenVerifier, err := oauth.NewTokenVerifier(
		oauth.Issuer(sts.Endpoint()),
		rp.NewRemoteKeySet(http.DefaultClient, sts.Endpoint("jwks")),
		string(jose.ES256),
	)
	require.NoError(t, err)

	verifier, err := oauth.NewMultiIssuerTokenVerifier(tokenVerifier)
	require.NoError(t, err)
	rawClaims, err := verifier.Verify(t.Context(), response.AccessToken)
	require.NoError(t, err)

	claims := new(oauth.STSTokenClaims)
	data, err := json.Marshal(rawClaims.Claims)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, claims))

	assert.Equal(t, sts.Endpoint(), claims.Issuer)
	assert.Equal(t, oidc.Audience{target}, claims.Audience)
	assert.Equal(t, clientID, claims.ClientID)
	assert.Equal(t, oauth.Roles{fixtures.Role}, claims.ApplicationRoles)
	assert.NotEmpty(t, claims.JWTID)

	now := time.Now()
	assert.WithinDuration(t, now, claims.IssuedAt.AsTime(), 10*time.Second)
	assert.Equal(t, claims.IssuedAt.AsTime(), claims.NotBefore.AsTime())
	assert.Equal(t, fixtures.TokenExpiry, claims.Expiration.AsTime().Sub(claims.IssuedAt.AsTime()))

	fn(claims)
	return rawClaims
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

	subjectTokenVerifier, err := oauth.ExternalTokenVerifier(t.Context(), http.DefaultClient, oauth.Issuer(oauthServer.Endpoint(issuer)))
	require.NoError(t, err)

	verifier, err := oauth.NewMultiIssuerTokenVerifier(subjectTokenVerifier)
	require.NoError(t, err)

	claims, err := verifier.Verify(t.Context(), token.AccessToken)
	require.NoError(t, err)

	return token.AccessToken, claims
}

func signSoftwareStatement(t testing.TB, statement registration.SoftwareStatement) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Key: jose.JSONWebKey{
		Key:   key,
		KeyID: "foo",
	}, Algorithm: jose.RS256}, nil)
	require.NoError(t, err)

	signed, err := crypto.Sign(statement, signer)
	require.NoError(t, err)
	return signed
}

func tamperJWTSignature(t testing.TB, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	require.NotEmpty(t, parts[2])

	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	return strings.Join(parts, ".")
}

func postRegistration[T any](t testing.TB, sts testServer, token string, body any) (int, *T) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sts.Endpoint("v1", "registration", "client"), bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	return registrationRequest[T](t, req)
}

func deleteRegistration[T any](t testing.TB, sts testServer, token, id string) (int, *T) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, sts.Endpoint("v1", "registration", "client", id), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	return registrationRequest[T](t, req)
}

func registrationRequest[T any](t testing.TB, req *http.Request) (int, *T) {
	t.Helper()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer ioconvenience.CloseWithLog(resp.Body, slog.Default())

	if resp.StatusCode == http.StatusNoContent {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Empty(t, body)
		return resp.StatusCode, nil
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	require.NoError(t, err)
	require.Equal(t, "application/json", mediaType)

	response := new(T)
	decoder := json.NewDecoder(resp.Body)
	require.NoError(t, decoder.Decode(response))
	var trailing any
	require.ErrorIs(t, decoder.Decode(&trailing), io.EOF)
	return resp.StatusCode, response
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
