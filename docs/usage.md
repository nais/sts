# Client usage

## Endpoints

| Method | Path                                      | Description                                                       |
|--------|-------------------------------------------|-------------------------------------------------------------------|
| `GET`  | `/.well-known/oauth-authorization-server` | Advertises the token endpoint, supported grants, and JWKS URI.    |
| `GET`  | `/jwks`                                   | Serves STS signing public keys.                                   |
| `POST` | `/token`                                  | Accepts form-encoded requests for an access token for one target. |

STS supports only token exchange. The discovery document advertises:

```json
{
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ]
}
```

Token requests require at least one configured `authorizationServer.subjectTokenIssuers` entry.
Without one, the token endpoint returns `unsupported_grant_type`.

## Authentication

Token exchange requires a projected Kubernetes service account token as `client_assertion`.
STS uses its issuer, namespace, and service account name to find the registered client.

Nais `Application` and `NaisJob` workloads get a token automatically at `NAIS_SERVICE_ACCOUNT_TOKEN_PATH`.
For raw Kubernetes workloads, mount a projected token:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-workload
  namespace: namespace1
---
apiVersion: v1
kind: Pod
metadata:
  name: my-workload
  namespace: namespace1
spec:
  serviceAccountName: my-workload
  containers:
    - name: my-workload
      image: my-image
      volumeMounts:
        - name: nais-token
          mountPath: /var/run/secrets/nais.io
          readOnly: true
  volumes:
    - name: nais-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: nais
              expirationSeconds: 600
```

- `audience` must match `authorizationServer.expectedAudience` (normally `nais`).
- Keep `expirationSeconds` within `authorizationServer.maxClientAuthTokenLifetime` (default `1h`).

For reference, a decoded projected service account token can contain:

```json
{
  "iss": "https://issuer.example.com/env1",
  "sub": "system:serviceaccount:namespace1:my-workload",
  "aud": ["nais"],
  "iat": 1790000000,
  "exp": 1790000600,
  "kubernetes.io": {
    "namespace": "namespace1",
    "serviceaccount": { "name": "my-workload" }
  }
}
```

The timestamps are illustrative; Kubernetes sets them when it issues the token.

## Token exchange

Send a subject JWT from an accepted issuer, or an STS access token from a previous token exchange.
Send exactly one target client ID in `audience`.
The target's authorization policy must allow the requesting client; it supplies the roles in the issued token.

STS verifies the subject token's signature, issuer, subject, and timestamps.
When the subject token is from STS, its `urn:nais:grant_type` must be `urn:ietf:params:oauth:grant-type:token-exchange`.

### Request

In this example, `subject_token` is a signed JWT from the accepted issuer `https://identity.example.com`.
Its decoded claims appear beside the issued token below.

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=<projected-service-account-token>&
audience=env1%3Anamespace1%3Atarget&
subject_token=<subject-JWT>&
subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&
requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
```

The body has line breaks for readability. Send the encoded parameters on one line.

| Field                   | Description                                                                  | Example value                                            |
|-------------------------|------------------------------------------------------------------------------|----------------------------------------------------------|
| `grant_type`            | Token exchange grant.                                                        | `urn:ietf:params:oauth:grant-type:token-exchange`        |
| `client_assertion_type` | JWT bearer assertion type.                                                   | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion`      | The projected service account token.                                         | `<projected-service-account-token>`                      |
| `audience`              | One target client ID whose policy lists the requesting client as a consumer. | `env1:namespace1:target`                                 |
| `subject_token`         | JWT to exchange from an accepted issuer, or a previous STS token exchange.   | `<subject-JWT>`                                          |
| `subject_token_type`    | Type of the incoming subject token.                                          | `urn:ietf:params:oauth:token-type:jwt`                   |
| `requested_token_type`  | Type of the requested token.                                                 | `urn:ietf:params:oauth:token-type:access_token`          |

### Response

```json
{
  "access_token": "<signed-STS-JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Exchanged token

In this example, STS configures `identity` as the alias for `https://identity.example.com`.
The decoded tokens compare as follows (timestamps and token IDs are illustrative):

<table>
<thead><tr><th>Subject token</th><th>Exchanged token</th></tr></thead>
<tbody><tr><td><pre><code>{
  "iss": "https://identity.example.com",
  "sub": "user-123",
  "department": "finance",
  "aud": ["external-service"],
  "jti": "b23c5d67-8901-4efa-9bcd-2345678901bc",
  "iat": 1789999700,
  "nbf": 1789999700,
  "exp": 1790000600,
  "act": {
    "sub": "external-actor",
    "act": { "sub": "earlier-actor" }
  }
}</code></pre></td><td><pre><code>{
  "iss": "https://sts.example.com",
  "sub": "user-123",
  "department": "finance",
  "aud": ["env1:namespace1:target"],
  "client_id": "env1:namespace1:my-workload",
  "jti": "a12b4c56-7890-4def-8abc-1234567890ab",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000900,
  "urn:nais:roles": ["reader"],
  "urn:nais:grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "urn:nais:idp": "https://identity.example.com",
  "urn:nais:idp_name": "identity",
  "act": {
    "sub": "external-actor",
    "act": { "sub": "earlier-actor" }
  },
  "urn:nais:call_chain": ["env1:namespace1:my-workload"]
}</code></pre></td></tr></tbody>
</table>

STS starts with the subject token's claims, then sets these values in the exchanged token:

| Claim                 | Value in exchanged token                                  | Changes compared to subject token claim                          |
|-----------------------|-----------------------------------------------------------|------------------------------------------------------------------|
| `iss`                 | STS issuer.                                               | Replaces the subject token's issuer.                             |
| `aud`                 | Target client ID from the request's `audience`.           | Replaces the subject token's audience.                           |
| `client_id`           | Requesting client ID.                                     | Added, or replaces an existing value.                            |
| `jti`                 | New token ID.                                             | Added, or replaces an existing value.                            |
| `iat`, `nbf`, `exp`   | New validity times.                                       | Added, or replace existing values.                               |
| `urn:nais:roles`      | Roles from the target's policy for the requesting client. | Added, or replaces an existing value.                            |
| `urn:nais:grant_type` | Always `urn:ietf:params:oauth:grant-type:token-exchange`. | Added, or replaces an existing value.                            |
| `urn:nais:idp`        | Issuer URL of the first subject token exchanged.          | Added on the first exchange; retained on later STS exchanges.    |
| `urn:nais:idp_name`   | Short, stable alias for that issuer.                      | Added on the first exchange; retained on later STS exchanges.    |
| `urn:nais:call_chain` | Client IDs in exchange order, oldest first.               | Added; appends the requesting client ID to a prior STS call chain. |

The `sub` claim and other claims, such as `department` and `act` in the example, keep their values.
Workloads can use `urn:nais:idp_name` to distinguish original issuers without depending on their exact URLs.
`urn:nais:call_chain` lists the client IDs that performed each exchange, oldest first.
STS preserves the chain from STS-issued subject tokens as history, not as authorization policy input. It ignores any `urn:nais:call_chain` in external subject tokens. A malformed chain in an STS-issued subject token starts a new chain.
STS does not add or extend `act`; [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1) reserves it for delegation with an `actor_token`, which STS does not support.

### Chained exchange

Client `env1:namespace1:target` uses the exchanged token above as its `subject_token` to request a token for `env1:namespace1:next-target`.
The requesting client is appended to the previous `urn:nais:call_chain` array:

<table>
<thead><tr><th>Subject token</th><th>Exchanged token</th></tr></thead>
<tbody><tr><td><pre><code>{
  "iss": "https://sts.example.com",
  "sub": "user-123",
  "department": "finance",
  "aud": ["env1:namespace1:target"],
  "client_id": "env1:namespace1:my-workload",
  "jti": "a12b4c56-7890-4def-8abc-1234567890ab",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000900,
  "urn:nais:roles": ["reader"],
  "urn:nais:grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "urn:nais:idp": "https://identity.example.com",
  "urn:nais:idp_name": "identity",
  "act": {
    "sub": "external-actor",
    "act": { "sub": "earlier-actor" }
  },
  "urn:nais:call_chain": ["env1:namespace1:my-workload"]
}</code></pre></td><td><pre><code>{
  "iss": "https://sts.example.com",
  "sub": "user-123",
  "department": "finance",
  "aud": ["env1:namespace1:next-target"],
  "client_id": "env1:namespace1:target",
  "jti": "c34d6e78-9012-4fab-8cde-3456789012cd",
  "iat": 1790000300,
  "nbf": 1790000300,
  "exp": 1790001200,
  "urn:nais:roles": ["writer"],
  "urn:nais:grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "urn:nais:idp": "https://identity.example.com",
  "urn:nais:idp_name": "identity",
  "act": {
    "sub": "external-actor",
    "act": { "sub": "earlier-actor" }
  },
  "urn:nais:call_chain": ["env1:namespace1:my-workload", "env1:namespace1:target"]
}</code></pre></td></tr></tbody>
</table>

## Errors

Error responses follow [RFC 6749, section 5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).

```json
{
  "error": "invalid_client",
  "error_description": "client assertion is invalid: token has expired"
}
```

The description names problems in the caller's own input, such as an untrusted issuer or a wrong audience.
It does not include internal details.
STS logs the full cause.

| `error`                  | Cause                                                                       |
|--------------------------|-----------------------------------------------------------------------------|
| `invalid_request`        | A request parameter, such as the subject token, is missing or invalid.      |
| `unsupported_grant_type` | STS does not support the grant type.                                        |
| `invalid_client`         | The client assertion is invalid, or the client is unknown.                  |
| `invalid_target`         | The target is invalid, or the client is not authorized for it.              |
| `server_error`           | An internal error occurred. The status is `500`.                            |

Malformed requests use status `400`, except for an unsupported content type.
A body that is not `application/x-www-form-urlencoded` returns `415`.
An oversized body returns `400` with `invalid_request` and the description `invalid request body`.
