# Client registration

STS registers Kubernetes workload clients on its public listener.

This API borrows from [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html),
but does not fully implement it or [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html).

## Endpoints

| Method   | Path                           | Result                                                          |
|----------|--------------------------------|-----------------------------------------------------------------|
| `POST`   | `/v1/registration/client`      | Create or replace a client; return `200 OK`.                    |
| `DELETE` | `/v1/registration/client/{id}` | Delete a client; return `204 No Content` even if it is missing. |

## Authentication

Send `Authorization: Bearer <token>` with either request. For example, given
this [STS configuration](configuration.md):

```yaml
authorizationServer:
  expectedAudience: nais
  maxClientAuthTokenLifetime: 1h
  clientAuthIssuers:
    - https://issuer.example.com/env1

registrators:
  - issuer: https://issuer.example.com/env1
    subject: client-registrator
    clientJwksUri: https://registrator.example.com/jwks
    requiredAlgs: [RS256]
```

The bearer token's decoded claims look like this:

```json
{
  "iss": "https://issuer.example.com/env1",
  "sub": "client-registrator",
  "aud": "nais",
  "iat": 1790000000,
  "exp": 1790003600
}
```

STS checks the bearer token against the configuration:

- `iss` matches `registrators[0].issuer` and appears in `clientAuthIssuers`.
- `sub` matches `registrators[0].subject`.
- `aud` contains only `expectedAudience`: `nais`.
- `iat` and `exp` are valid timestamps. STS allows one minute of clock skew
  when it checks both claims.
- `exp` must follow `iat`. The lifetime (`exp` - `iat`) cannot exceed
  `maxClientAuthTokenLifetime` plus one minute. In this example, the limit is
  one hour and one minute.

## Software statement

The registrator must create and sign a [software statement](https://www.rfc-editor.org/rfc/rfc7591.html#section-2.3).
A registrator cannot manage another issuer's clients.

### Claims

The signed JWT contains these claims:

```json
{
  "client_id": "env1:namespace1:my-workload",
  "workload": {
    "environment": "env1",
    "issuer": "https://issuer.example.com/env1",
    "namespace": "namespace1",
    "workload": "my-workload"
  },
  "authorization_policies": [
    {
      "consumer": "env1:namespace1:consumer",
      "roles": ["reader"]
    }
  ]
}
```

| Claim                               | Description                                                                        | Example value                                                       |
|-------------------------------------|------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| `client_id`                         | Identifier chosen for the client.                                                  | `env1:namespace1:my-workload`                                       |
| `workload.environment`              | Environment where the workload runs.                                               | `env1`                                                              |
| `workload.issuer`                   | Issuer of the workload's identity token. It must match the registrator's `issuer`. | `https://issuer.example.com/env1`                                   |
| `workload.namespace`                | Kubernetes namespace of the workload.                                              | `namespace1`                                                        |
| `workload.workload`                 | Kubernetes service account name of the workload.                                   | `my-workload`                                                       |
| `authorization_policies`            | Rules for which consumers can request tokens targeting this client.                | `[{ "consumer": "env1:namespace1:consumer", "roles": ["reader"] }]` |
| `authorization_policies[].consumer` | Consumer client ID. Registration does not require that consumer to exist.          | `env1:namespace1:consumer`                                          |
| `authorization_policies[].roles`    | Roles STS adds to tokens issued to this consumer for this client.                  | `["reader"]`                                                        |

In this example, `env1:namespace1:consumer` is granted permission to request a token targeting `my-workload`.
STS adds all roles from the policy, including `reader`, to the issued token.

### Public key

The configured `clientJwksUri` must point to an endpoint that serves a [JWKS](https://www.rfc-editor.org/rfc/rfc7517.html#section-5)
containing the corresponding public key used to sign the statement.

For the configuration above:

```http
GET /jwks HTTP/1.1
Host: registrator.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "registration-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "<omitted for brevity>",
      "e": "AQAB"
    }
  ]
}
```

The JWT header's `kid` must match a published key.
Its `alg` must match one of the registrator's `requiredAlgs`. In this example, it must be `RS256`.

## Create or replace a client

### Request

```http
POST /v1/registration/client HTTP/1.1
Authorization: Bearer <registrator token>
Content-Type: application/json

{
  "software_statement": "<signed JWT>"
}
```

On a repeated `POST` for the same client:

- STS replaces its authorization policies.
- The following fields are immutable:
  - `client_id`
  - `workload.environment`
  - `workload.namespace`
  - `workload.workload`
  - `workload.issuer`
- A change to an immutable field returns `400 Bad Request` with `invalid_client_metadata`.
- A workload that another client already uses returns the same error.

### Response

Both creation and replacement return:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "client_id": "env1:namespace1:my-workload",
  "software_statement": "<signed JWT>"
}
```

STS returns the supplied JWT and takes `client_id` from its verified claims.

## Delete a client

### Request

```http
DELETE /v1/registration/client/env1:namespace1:my-workload HTTP/1.1
Authorization: Bearer <registrator token>
```

### Response

Deleted or already absent:

```http
HTTP/1.1 204 No Content
```

## Errors

Error responses use the format from [RFC 6749, section 5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).

```json
{
  "error": "invalid_software_statement",
  "error_description": "software statement is invalid: invalid signature"
}
```

The description names the check that failed.
STS logs the full cause.

| Status | `error`                         | Defined in                                                              | Cause                                                                                           |
|--------|---------------------------------|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| 400    | `invalid_request`               | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2)     | The client ID in the path is invalid.                                                           |
| 400    | `invalid_client_metadata`       | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.2)   | The body is invalid, the request changes immutable fields, or another client uses the workload. |
| 400    | `invalid_software_statement`    | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.2)   | The software statement has an invalid signature or invalid content.                             |
| 400    | `unapproved_software_statement` | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.2)   | The workload issuer does not match the registrator issuer.                                      |
| 400    | `unauthorized_client`           | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2)     | The client belongs to another registrator issuer.                                               |
| 401    | `invalid_token`                 | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)     | Registrator authentication failed.                                                              |
| 400    | `invalid_request`               | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2)     | The body is too large.                                                                          |
| 415    | `invalid_request`               | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2)     | The content type is not `application/json`.                                                     |
| 500    | `server_error`                  | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1) | An internal error occurred.                                                                     |
