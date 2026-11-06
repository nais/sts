//go:build integration_test

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/ioconvenience"
	"github.com/nais/sts/internal/jwt"
	"github.com/nais/sts/internal/oauth"
	"github.com/nais/sts/internal/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestSts(t *testing.T) {
	oauthServer := startMockOAuthServer(t)

	stsConfig := startSts(t, oauthServer)
	stsAddress := stsConfig.Address

	t.Run("discovery", func(t *testing.T) {
		resp := get[api.DiscoveryMetadata](t, stsAddress.Endpoint(".well-known", "oauth-authorization-server"))
		assert.Equal(t, stsAddress.Endpoint(), resp.Issuer)
		assert.Equal(t, stsAddress.Endpoint("token"), resp.TokenEndpoint)
		assert.Equal(t, stsAddress.Endpoint("jwks"), resp.JwksURI)

		assert.Equal(t, []api.GrantType{
			api.GrantTypeClientCredentials,
			api.GrantTypeTokenExchange,
		}, resp.GrantTypesSupported)

		assert.Equal(t, []api.AuthMethod{api.AuthMethodPrivateKeyJWT}, resp.TokenEndpointAuthMethodsSupported)
	})

	t.Run("registration", func(t *testing.T) {
		registratorToken := getKubernetesToken(t, oauthServer, fixtures.RegisteredTarget.Environment, fixtures.RegisteredTarget.Namespace, "registrator1")
		otherRegistratorToken := getKubernetesToken(t, oauthServer, "env2", fixtures.RegisteredTarget.Namespace, "registrator2")
		statement := registration.SoftwareStatement{
			Client: fixtures.RegisteredTarget.apiClient(),
			AuthorizationPolicies: []api.AuthorizationPolicy{
				{
					Consumer: fixtures.Client1.apiClient(),
					Roles:    []string{fixtures.Role},
				},
			},
		}
		statementClientID := fixtures.RegisteredTarget.ID
		signed := signSoftwareStatement(t, statement)

		// These subtests share one registration from creation through deletion.
		t.Run("accepts valid registration", func(t *testing.T) {
			request := api.ClientRegistration{
				SoftwareStatement: signed,
			}
			status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, request)
			require.Equal(t, http.StatusOK, status, response)
			assert.Equal(t, statementClientID, response.ClientID)
			assert.Equal(t, signed, response.SoftwareStatement)

			consumer := fixtures.Client1
			target := statementClientID

			clientAssertion := getClientToken(t, oauthServer, consumer)
			clientCredentials := stsToken[oauth.AccessTokenResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))
			require.NotEmpty(t, clientCredentials.AccessToken)

			const subjectIssuer = "subject1"
			subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
			tokenExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))
			require.NotEmpty(t, tokenExchange.AccessToken)
		})

		t.Run("replaces registration", func(t *testing.T) {
			// Replacing registered-workload's policies removes Client1's grant.
			withoutGrant := statement
			withoutGrant.AuthorizationPolicies = nil
			status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, withoutGrant),
			})
			require.Equal(t, http.StatusOK, status, response)
			assert.Equal(t, statementClientID, response.ClientID)

			consumer := fixtures.Client1
			target := statementClientID

			// Wait for the cache to stop authorizing Client1 for registered-workload.
			clientAssertion := getClientToken(t, oauthServer, consumer)
			assertTokenDenialAfterRefresh(t,
				stsAddress,
				clientCredentialsForm(clientAssertion, target),
				"invalid_target",
				fmt.Sprintf("client is not authorized for target %q", target),
			)

			// Restore registered-workload's grant to Client1 for later tests.
			status, response = postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signed,
			})
			require.Equal(t, http.StatusOK, status, response)
			assert.Equal(t, signed, response.SoftwareStatement)
		})

		t.Run("registers another client", func(t *testing.T) {
			another := statement
			another.Client.Name = "another-workload"
			anotherClientID := "env1:namespace1:another-workload"
			another.AuthorizationPolicies = []api.AuthorizationPolicy{
				{
					Consumer: fixtures.Client3.apiClient(),
					Roles:    []string{fixtures.Role},
				},
			}

			status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, another),
			})
			require.Equal(t, http.StatusOK, status, response)

			consumer := fixtures.Client3
			target := anotherClientID

			clientAssertion := getClientToken(t, oauthServer, consumer)
			token := stsToken[oauth.AccessTokenResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))
			require.NotEmpty(t, token.AccessToken)

			status, _ = deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, anotherClientID)
			require.Equal(t, http.StatusNoContent, status)
		})

		for _, roles := range []string{"omitted", "empty"} {
			t.Run("registers policy with "+roles+" roles before consumer", func(t *testing.T) {
				consumer := newClientFixture("env1", "namespace1", roles+"-roles-consumer")
				target := statement
				targetClientID := "env1:namespace1:" + roles + "-roles-target"
				target.Client.Name = roles + "-roles-target"
				policy := map[string]any{"consumer": consumer.apiClient()}
				if roles == "empty" {
					policy["roles"] = []string{}
				}
				status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
					SoftwareStatement: signSoftwareStatement(t, map[string]any{
						"client":                 target.Client,
						"authorization_policies": []map[string]any{policy},
					}),
				})
				require.Equal(t, http.StatusOK, status, response)

				clientAssertion := getClientToken(t, oauthServer, consumer)
				denial := stsToken[errs.ErrorResponse](t, stsAddress, clientCredentialsForm(clientAssertion, targetClientID))
				require.Equal(t, "invalid_client", denial.Code)

				status, response = postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
					SoftwareStatement: signSoftwareStatement(t, api.SoftwareStatement{Client: consumer.apiClient()}),
				})
				require.Equal(t, http.StatusOK, status, response)

				subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, "subject1")
				for grant, form := range map[string]url.Values{
					"client credentials": clientCredentialsForm(clientAssertion, targetClientID),
					"token exchange":     tokenExchangeForm(clientAssertion, subjectToken, targetClientID),
				} {
					t.Run(grant, func(t *testing.T) {
						token := stsToken[oauth.AccessTokenResponse](t, stsAddress, form)
						claims := assertTokenClaims(t, stsAddress, token, targetClientID, consumer.ID, func(claims *oauth.STSTokenClaims) {
							assert.Equal(t, oidc.GrantType(form.Get("grant_type")), claims.GrantType)
						}, oauth.Roles(nil))
						assert.NotContains(t, claims.Claims, "urn:nais:roles")
					})
				}

				for _, id := range []string{targetClientID, consumer.ID} {
					status, _ := deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, id)
					require.Equal(t, http.StatusNoContent, status)
				}
			})
		}

		t.Run("authorizes policy consumer in every environment", func(t *testing.T) {
			target := statement
			target.Client.Name = "multi-environment-target"
			targetClientID := "env1:namespace1:multi-environment-target"
			consumer := newClientFixture("env2", "namespace1", "multi-environment-consumer")
			target.AuthorizationPolicies = []api.AuthorizationPolicy{{Consumer: consumer.apiClient()}}

			status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, target),
			})
			require.Equal(t, http.StatusOK, status, response)

			// The env2 registrator owns the consumer and receives an env2 client ID.
			status, response = postRegistration[api.ClientRegistrationResponse](t, stsAddress, otherRegistratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, api.SoftwareStatement{Client: consumer.apiClient()}),
			})
			require.Equal(t, http.StatusOK, status, response)
			require.Equal(t, consumer.ID, response.ClientID)

			clientAssertion := getClientToken(t, oauthServer, consumer)
			token := stsToken[oauth.AccessTokenResponse](t, stsAddress, clientCredentialsForm(clientAssertion, targetClientID))
			require.NotEmpty(t, token.AccessToken)

			status, _ = deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, targetClientID)
			require.Equal(t, http.StatusNoContent, status)
			status, _ = deleteRegistration[errs.ErrorResponse](t, stsAddress, otherRegistratorToken, consumer.ID)
			require.Equal(t, http.StatusNoContent, status)
		})

		t.Run("consumer cannot grant itself access to another target", func(t *testing.T) {
			selfGrant := statement
			selfGrant.Client.Name = "self-grant-workload"
			selfGrant.AuthorizationPolicies = []api.AuthorizationPolicy{
				{Consumer: fixtures.Client3.apiClient(), Roles: []string{fixtures.Role}},
			}

			status, response := postRegistration[api.ClientRegistrationResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, selfGrant),
			})
			require.Equal(t, http.StatusOK, status, response)

			consumer := newClientFixture("env1", selfGrant.Client.Namespace, selfGrant.Client.Name)
			target := fixtures.Client3.ID

			// A policy owned by the consumer cannot authorize client credentials for Client3.
			clientAssertion := getClientToken(t, oauthServer, consumer)
			clientCredentials := stsToken[errs.ErrorResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))
			assert.Equal(t, "invalid_target", clientCredentials.Code)
			assert.Equal(t, fmt.Sprintf("client is not authorized for target %q", target), clientCredentials.Description)

			// A policy owned by the consumer cannot authorize token exchange for Client3.
			const subjectIssuer = "subject1"
			subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
			tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))
			assert.Equal(t, "invalid_target", tokenExchange.Code)
			assert.Equal(t, fmt.Sprintf("client is not authorized for target %q", target), tokenExchange.Description)

			status, _ = deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, consumer.ID)
			require.Equal(t, http.StatusNoContent, status)
		})

		t.Run("does not delete registration outside issuer authority", func(t *testing.T) {
			status, response := deleteRegistration[errs.ErrorResponse](t, stsAddress, otherRegistratorToken, statementClientID)
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Equal(t, "unauthorized_client", response.Code)
		})

		t.Run("deletes missing registration", func(t *testing.T) {
			status, _ := deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, "env1:namespace1:missing")
			require.Equal(t, http.StatusNoContent, status)
		})

		t.Run("rejects invalid software statement signature", func(t *testing.T) {
			request := api.ClientRegistration{
				SoftwareStatement: tamperJWTSignature(t, signed),
			}
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, request)
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Equal(t, "invalid_software_statement", response.Code)
			assert.Equal(t, "software statement is invalid", response.Description)
		})

		t.Run("rejects invalid signed software statement claims", func(t *testing.T) {
			invalid := statement
			invalid.Client.Name = "Invalid"
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: signSoftwareStatement(t, invalid),
			})
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Equal(t, "software statement is invalid", response.Description)
		})

		t.Run("rejects unauthorized registrator", func(t *testing.T) {
			unauthorizedToken := getKubernetesToken(t, oauthServer, fixtures.Client1.Environment, fixtures.Client1.Namespace, "not-a-registrator")
			request := api.ClientRegistration{
				SoftwareStatement: signed,
			}
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, unauthorizedToken, request)
			require.Equal(t, http.StatusUnauthorized, status, response)
			assert.Equal(t, "invalid_token", response.Code)
			assert.Equal(t, "authentication failed", response.Description)
		})

		t.Run("rejects malformed request", func(t *testing.T) {
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, map[string]any{
				"software_statement": signed,
				"unknown":            true,
			})
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Equal(t, "invalid request body", response.Description)
		})

		t.Run("rejects unsupported content type", func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(),
				http.MethodPost,
				stsAddress.Endpoint("v1", "registration", "client"),
				strings.NewReader("{}"),
			)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("Authorization", "Bearer "+registratorToken)

			status, response := registrationRequest[errs.ErrorResponse](t, req)
			require.Equal(t, http.StatusUnsupportedMediaType, status, response)
			assert.Equal(t, "content type must be application/json", response.Description)
		})

		t.Run("rejects oversized request", func(t *testing.T) {
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, api.ClientRegistration{
				SoftwareStatement: strings.Repeat("x", 65<<10),
			})
			require.Equal(t, http.StatusBadRequest, status, response)
			assert.Equal(t, "invalid request body", response.Description)
		})

		t.Run("rejects missing bearer token", func(t *testing.T) {
			status, response := postRegistration[errs.ErrorResponse](t, stsAddress, "", api.ClientRegistration{
				SoftwareStatement: signed,
			})
			require.Equal(t, http.StatusUnauthorized, status, response)
			assert.Equal(t, "authentication failed", response.Description)
		})

		for _, id := range []string{
			"1client",
			"Client",
			"client-",
			"client:",
			"client",
			"env1:namespace1",
			"env1:namespace1:name:extra",
			"client_name",
			"client.name",
		} {
			t.Run("rejects invalid client ID "+id, func(t *testing.T) {
				status, response := deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, id)
				require.Equal(t, http.StatusBadRequest, status, response)
				assert.Equal(t, "client ID is invalid", response.Description)
			})
		}

		t.Run("deletes registration with valid client ID", func(t *testing.T) {
			status, _ := deleteRegistration[errs.ErrorResponse](t, stsAddress, registratorToken, statementClientID)
			require.Equal(t, http.StatusNoContent, status)

			// registered-workload cannot request a token after its registration is deleted.
			consumer := fixtures.RegisteredTarget
			target := fixtures.Client2.ID

			clientAssertion := getClientToken(t, oauthServer, consumer)
			assertTokenDenialAfterRefresh(t,
				stsAddress,
				clientCredentialsForm(clientAssertion, target),
				"invalid_client",
				"client authentication failed",
			)

			// Client1 cannot request a token targeting registered-workload after its policy is deleted.
			consumer = fixtures.Client1
			target = statementClientID

			clientAssertion = getClientToken(t, oauthServer, consumer)
			assertTokenDenialAfterRefresh(t,
				stsAddress,
				clientCredentialsForm(clientAssertion, target),
				"invalid_target",
				fmt.Sprintf("client is not authorized for target %q", target),
			)
		})
	})

	t.Run("client credentials", func(t *testing.T) {
		consumer := fixtures.Client1
		target := fixtures.Client2.ID

		clientAssertion := getClientToken(t, oauthServer, consumer)
		clientCredentials := stsToken[oauth.AccessTokenResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))

		assert.Equal(t, oidc.BearerToken, clientCredentials.TokenType)
		assert.Empty(t, clientCredentials.IssuedTokenType)
		assertTokenClaims(t, stsAddress, clientCredentials, target, consumer.ID, func(claims *oauth.STSTokenClaims) {
			assert.Equal(t, consumer.ID, claims.Subject)
			assert.Equal(t, oidc.GrantTypeClientCredentials, claims.GrantType)
			assert.Nil(t, claims.Actor)
		})
	})

	t.Run("client credentials denies unauthorized scope", func(t *testing.T) {
		consumer := fixtures.Client1
		target := "env1:namespace1:unauthorized"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		clientCredentials := stsToken[errs.ErrorResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))

		assert.Equal(t, "invalid_target", clientCredentials.Code)
		assert.Equal(t, fmt.Sprintf("client is not authorized for target %q", target), clientCredentials.Description)
	})

	t.Run("client credentials denies unregistered client", func(t *testing.T) {
		consumer := clientFixture{
			Environment: fixtures.Client1.Environment,
			Namespace:   fixtures.Client1.Namespace,
			Name:        "unregistered",
		}
		target := fixtures.Client2.ID

		clientAssertion := getClientToken(t, oauthServer, consumer)
		clientCredentials := stsToken[errs.ErrorResponse](t, stsAddress, clientCredentialsForm(clientAssertion, target))

		assert.Equal(t, "invalid_client", clientCredentials.Code)
		assert.Equal(t, "client authentication failed", clientCredentials.Description)
	})

	t.Run("client credentials denies untrusted client assertion issuer", func(t *testing.T) {
		const issuer = "untrusted"

		clientAssertion := getKubernetesToken(t, oauthServer, issuer, fixtures.Client1.Namespace, fixtures.Client1.Name)
		clientCredentials := stsToken[errs.ErrorResponse](t, stsAddress, clientCredentialsForm(clientAssertion, fixtures.Client2.ID))

		assert.Equal(t, "invalid_client", clientCredentials.Code)
		assert.Equal(t, "client assertion is invalid", clientCredentials.Description)
	})

	t.Run("token exchange", func(t *testing.T) {
		consumer := fixtures.Client1
		target := fixtures.Client2.ID
		const subjectIssuer = "subject1"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		subjectToken, subjectClaims := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		tokenExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))

		assert.Equal(t, oidc.BearerToken, tokenExchange.TokenType)
		assert.Equal(t, oidc.AccessTokenType, tokenExchange.IssuedTokenType)
		assertTokenExchangeClaims(t, stsConfig, tokenExchange, subjectClaims, target, consumer.ID)
		assertTokenActor(t, stsAddress, tokenExchange, target, consumer.ID, nil)
	})

	t.Run("token exchange with STS issued token", func(t *testing.T) {
		firstConsumer := fixtures.Client1
		firstTarget := fixtures.Client2.ID
		const subjectIssuer = "subject1"

		firstClientAssertion := getClientToken(t, oauthServer, firstConsumer)
		subjectToken, subjectClaims := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		firstExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(firstClientAssertion, subjectToken, firstTarget))

		assert.Equal(t, oidc.BearerToken, firstExchange.TokenType)
		assert.Equal(t, oidc.AccessTokenType, firstExchange.IssuedTokenType)
		assertTokenExchangeClaims(t, stsConfig, firstExchange, subjectClaims, firstTarget, firstConsumer.ID)
		firstActor := assertTokenActor(t, stsAddress, firstExchange, firstTarget, firstConsumer.ID, nil)

		secondConsumer := fixtures.Client2
		secondTarget := fixtures.Client3.ID

		secondClientAssertion := getClientToken(t, oauthServer, secondConsumer)
		secondExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(secondClientAssertion, firstExchange.AccessToken, secondTarget))

		assert.Equal(t, oidc.BearerToken, secondExchange.TokenType)
		assert.Equal(t, oidc.AccessTokenType, secondExchange.IssuedTokenType)
		assertTokenExchangeClaims(t, stsConfig, secondExchange, subjectClaims, secondTarget, secondConsumer.ID)
		assertTokenActor(t, stsAddress, secondExchange, secondTarget, secondConsumer.ID, firstActor)
	})

	t.Run("token exchange denies STS token issued to another client", func(t *testing.T) {
		consumer := fixtures.Client1
		target := fixtures.Client2.ID
		const subjectIssuer = "subject1"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)

		firstExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))
		secondExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, firstExchange.AccessToken, target))
		assert.Equal(t, "invalid_request", secondExchange.Code)
		assert.Equal(t, "subject token is invalid", secondExchange.Description)
	})

	t.Run("token exchange ignores external actor chain", func(t *testing.T) {
		firstConsumer := fixtures.Client1
		firstTarget := fixtures.Client2.ID
		const subjectIssuer = "subject2"

		firstClientAssertion := getClientToken(t, oauthServer, firstConsumer)
		subjectToken, subjectClaims := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		previous := subjectClaims.Claims["act"]
		require.JSONEq(t,
			`{"sub":"external-actor","custom":"original-identity","act":{"iss":"https://prior.example.com","sub":"earlier-actor"}}`,
			string(previous),
		)

		firstExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(firstClientAssertion, subjectToken, firstTarget))
		first := assertTokenClaims(t, stsAddress, firstExchange, firstTarget, firstConsumer.ID, func(claims *oauth.STSTokenClaims) {
			require.NotNil(t, claims.Actor)
			assert.Equal(t, firstConsumer.ID, claims.Actor.ClientID)
			assert.Empty(t, string(claims.Actor.Actor))
		})

		secondConsumer := fixtures.Client2
		secondTarget := fixtures.Client3.ID

		secondClientAssertion := getClientToken(t, oauthServer, secondConsumer)
		secondExchange := stsToken[oauth.AccessTokenResponse](t, stsAddress, tokenExchangeForm(secondClientAssertion, firstExchange.AccessToken, secondTarget))
		assertTokenClaims(t, stsAddress, secondExchange, secondTarget, secondConsumer.ID, func(claims *oauth.STSTokenClaims) {
			require.NotNil(t, claims.Actor)
			assert.Equal(t, secondConsumer.ID, claims.Actor.ClientID)
			assert.JSONEq(t, string(first.Claims["act"]), string(claims.Actor.Actor))
		})
	})

	t.Run("token exchange denies STS client credentials token", func(t *testing.T) {
		firstConsumer := fixtures.Client1
		firstTarget := fixtures.Client2.ID
		firstClientAssertion := getClientToken(t, oauthServer, firstConsumer)
		clientCredentials := stsToken[oauth.AccessTokenResponse](t, stsAddress, clientCredentialsForm(firstClientAssertion, firstTarget))

		secondConsumer := fixtures.Client2
		secondTarget := fixtures.Client3.ID
		secondClientAssertion := getClientToken(t, oauthServer, secondConsumer)
		tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(secondClientAssertion, clientCredentials.AccessToken, secondTarget))

		assert.Equal(t, "invalid_request", tokenExchange.Code)
		assert.Equal(t, "subject token is invalid", tokenExchange.Description)
	})

	t.Run("token exchange denies unauthorized audience", func(t *testing.T) {
		consumer := fixtures.Client1
		target := "env1:namespace1:unauthorized"
		const subjectIssuer = "subject1"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))

		assert.Equal(t, "invalid_target", tokenExchange.Code)
		assert.Equal(t, fmt.Sprintf("client is not authorized for target %q", target), tokenExchange.Description)
	})

	t.Run("token exchange denies unregistered client", func(t *testing.T) {
		consumer := clientFixture{
			Environment: fixtures.Client1.Environment,
			Namespace:   fixtures.Client1.Namespace,
			Name:        "unregistered",
		}
		target := fixtures.Client2.ID
		const subjectIssuer = "subject1"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))

		assert.Equal(t, "invalid_client", tokenExchange.Code)
		assert.Equal(t, "client authentication failed", tokenExchange.Description)
	})

	t.Run("token exchange denies untrusted client assertion issuer", func(t *testing.T) {
		const issuer = "untrusted"

		clientAssertion := getKubernetesToken(t, oauthServer, issuer, fixtures.Client1.Namespace, fixtures.Client1.Name)
		subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, "subject1")
		tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID))

		assert.Equal(t, "invalid_client", tokenExchange.Code)
		assert.Equal(t, "client assertion is invalid", tokenExchange.Description)
	})

	t.Run("token exchange denies untrusted subject token issuer", func(t *testing.T) {
		consumer := fixtures.Client1
		target := fixtures.Client2.ID
		const subjectIssuer = "untrusted"

		clientAssertion := getClientToken(t, oauthServer, consumer)
		subjectToken, _ := getSubjectTokenFromIssuer(t, oauthServer, subjectIssuer)
		tokenExchange := stsToken[errs.ErrorResponse](t, stsAddress, tokenExchangeForm(clientAssertion, subjectToken, target))

		assert.Equal(t, "invalid_request", tokenExchange.Code)
		assert.Equal(t, "subject token is invalid", tokenExchange.Description)
	})
}

func assertTokenActor(
	t *testing.T,
	sts testServer,
	response *oauth.AccessTokenResponse,
	targetID, consumerID string,
	previous *oauth.ActorClaims,
) *oauth.ActorClaims {
	t.Helper()
	var actor *oauth.ActorClaims
	assertTokenClaims(t, sts, response, targetID, consumerID, func(claims *oauth.STSTokenClaims) {
		actor = claims.Actor
		require.NotNil(t, actor)
		assert.Equal(t, consumerID, actor.ClientID)
		if previous == nil {
			assert.Empty(t, actor.Actor)
		} else {
			encoded, err := json.Marshal(previous)
			require.NoError(t, err)
			assert.JSONEq(t, string(encoded), string(actor.Actor))
		}
	})
	return actor
}

type claimAssertions func(claims *oauth.STSTokenClaims)

func assertTokenExchangeClaims(
	t *testing.T,
	stsConfig testServerConfig,
	response *oauth.AccessTokenResponse,
	subjectClaims *jwt.AccessTokenClaims,
	targetID, consumerID string,
) {
	t.Helper()

	idpName, ok := stsConfig.AuthServerConfig.SubjectTokenIssuers[jwt.Issuer(subjectClaims.Issuer)]
	require.True(t, ok, "subject token issuer %q not found in STS configuration", subjectClaims.Issuer)

	stsAddress := stsConfig.Address

	// Parse the issued token as typed STS claims and as a complete raw claim map.
	var stsClaims *oauth.STSTokenClaims
	issuedClaims := assertTokenClaims(t, stsAddress, response, targetID, consumerID, func(claims *oauth.STSTokenClaims) {
		stsClaims = claims
		assert.Equal(t, subjectClaims.Subject, claims.Subject)
		assert.Equal(t, oidc.GrantTypeTokenExchange, claims.GrantType)
		assert.Equal(t, subjectClaims.Issuer, claims.IDP)
		assert.Equal(t, idpName, claims.IDPName)
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

func assertTokenClaims(
	t *testing.T,
	sts testServer,
	response *oauth.AccessTokenResponse,
	targetID, consumerID string,
	fn claimAssertions,
	roles ...oauth.Roles,
) *jwt.AccessTokenClaims {
	t.Helper()
	require.NotEmpty(t, response.AccessToken)

	wantExpiresIn := uint64(fixtures.TokenExpiry.Seconds())
	assert.GreaterOrEqual(t, response.ExpiresIn, wantExpiresIn-10)
	assert.LessOrEqual(t, response.ExpiresIn, wantExpiresIn)

	verifier, err := jwt.NewTokenVerifier(t.Context(), jwt.WithIssuerAndKeySet(
		jwt.Issuer(sts.Endpoint()),
		rp.NewRemoteKeySet(http.DefaultClient, sts.Endpoint("jwks")),
		string(oauth.InternalSigningAlgorithm),
	))
	require.NoError(t, err)
	rawClaims, err := verifier.Verify(t.Context(), response.AccessToken)
	require.NoError(t, err)

	claims := new(oauth.STSTokenClaims)
	data, err := json.Marshal(rawClaims.Claims)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, claims))

	assert.Equal(t, sts.Endpoint(), claims.Issuer)
	assert.Equal(t, oidc.Audience{targetID}, claims.Audience)
	assert.Equal(t, consumerID, claims.ClientID)
	wantRoles := oauth.Roles{fixtures.Role}
	if len(roles) > 0 {
		wantRoles = roles[0]
	}
	assert.Equal(t, wantRoles, claims.ApplicationRoles)
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

func assertTokenDenialAfterRefresh(t *testing.T, sts testServer, form url.Values, code, description string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		resp := stsToken[errs.ErrorResponse](t, sts, form)
		return resp.Code == code && resp.Description == description
	}, 5*time.Second, 10*time.Millisecond)
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

func getClientToken(t testing.TB, oauthServer testServer, client clientFixture) string {
	t.Helper()
	return getKubernetesToken(t, oauthServer, client.Environment, client.Namespace, client.Name)
}

func getSubjectTokenFromIssuer(t testing.TB, oauthServer testServer, issuer string) (string, *jwt.AccessTokenClaims) {
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
	defer ioconvenience.Close(resp.Body)

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

	verifier, err := jwt.NewTokenVerifier(t.Context(), jwt.WithIssuer(jwt.Issuer(oauthServer.Endpoint(issuer))))
	require.NoError(t, err)

	claims, err := verifier.Verify(t.Context(), token.AccessToken)
	require.NoError(t, err)

	return token.AccessToken, claims
}

func signSoftwareStatement(t testing.TB, statement any) string {
	t.Helper()
	signed, err := signer.SignJWT(statement)
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
	defer ioconvenience.Close(resp.Body)

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

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "HTTP request")
	defer ioconvenience.Close(resp.Body)

	ret := new(T)
	if _, wantError := any(ret).(*errs.ErrorResponse); !wantError {
		require.Equal(t, http.StatusOK, resp.StatusCode, "HTTP status")
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(ret))
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
