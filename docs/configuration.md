# Configuration

STS reads one YAML configuration file.
Set `CONFIG_FILE` to change its path; the default is `config.yaml`.
Unknown fields and multi-document YAML files are rejected.
A nonempty `DATABASE_URL` environment variable overrides the file's `databaseUrl`
before validation. Otherwise, `databaseUrl` must be supplied in the file.

See [`config.example.yaml`](../sts-authserver/config.example.yaml) for a local example.
It sets `tokenExpiry` to `1h` instead of the `15m` default.

| Field                                             | Default   | Required | Constraints                                                   | Description                                                                                         |
|---------------------------------------------------|-----------|----------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `bindAddress`                                     | `:8080`   |          | Nonempty.                                                     | Public HTTP listener.                                                                               |
| `internalBindAddress`                             | `:8081`   |          | Nonempty.                                                     | Internal health and metrics listener.                                                               |
| `databaseUrl`                                     |           | Yes      | Nonempty unless supplied through `DATABASE_URL`.               | PostgreSQL connection URL; overridden by nonempty `DATABASE_URL`.                                    |
| `logLevel`                                        | `info`    |          |                                                               | Log level.                                                                                          |
| `logFormat`                                       | `text`    |          | `text` or `json`.                                             | Log format.                                                                                         |
| `authorizationServer.issuer`                      |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | STS issuer URL.                                                                                     |
| `authorizationServer.expectedAudience`            | `nais`    |          | Nonempty.                                                     | Sole audience for client assertions and registration bearer tokens.                                 |
| `authorizationServer.clientAuthIssuers`           |           | Yes      | At least one issuer.                                          | Accepted issuers for client assertions and registration bearer tokens.                              |
| `authorizationServer.clientAuthSigningAlgorithms` | `[RS256]` |          | Unique RS256/384/512, PS256/384/512, or ES256/384/512 values. | Allowed algorithms for client assertions and registration bearer tokens.                            |
| `authorizationServer.subjectTokenIssuers`         | `{}`      |          |                                                               | Accepted subject-token issuer URLs mapped to aliases. An empty map disables token exchange.         |
| `authorizationServer.maxClientAuthTokenLifetime`  | `1h`      |          | Positive duration.                                            | Maximum client assertion and registration bearer-token lifetime, plus one minute of tolerance.      |
| `authorizationServer.tokenExpiry`                 | `15m`     |          | Positive duration.                                            | Lifetime of access tokens issued by STS.                                                            |
| `registrators`                                    | `[]`      |          |                                                               | Authorities for client registration.                                                                |
| `registrators[].issuer`                           |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | Workload issuer this registrator controls.                                                          |
| `registrators[].subject`                          |           | Yes      | Nonempty.                                                     | Subject of the registrator's bearer token.                                                          |
| `registrators[].clientJwksUri`                    |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | URL of the public keys used to verify software statements.                                          |
| `registrators[].requiredAlgs`                     |           | Yes      | Unique RS256/384/512, PS256/384/512, or ES256/384/512 values. | Allowed software-statement signing algorithms.                                                      |

## Helm database credentials

The authserver chart depends on [`nais-postgresql`](https://github.com/nais/helm-charts/tree/main/charts/nais-postgresql), published from `nais/helm-charts`.
Its dependency alias remains `postgresql`, so configure it under that values key.
After changing the dependency version, run `helm dependency update charts/sts-authserver` and commit `Chart.lock`.
The selected version must be published before STS can build its dependencies.

With `postgresqlEnabled: true`, the authserver chart sets `DATABASE_URL` from the
CNPG-generated application's Secret (`<cluster-name>-app`, key `uri`). The Secret
name is built directly from `postgresql.fullnameOverride`, which defaults to
`sts-postgresql`. This value is required when the dependency is enabled and must
be a valid Cluster name of at most 50 characters. The parent does not call the
subchart's naming helper. No database password is copied into the configuration
Secret or Helm values.

Keep `postgresql.fullnameOverride` equal to the existing Cluster name when
upgrading; changing it creates a different Cluster. Multiple releases in the
same namespace need distinct overrides.

With `postgresqlEnabled: false`, the chart does not set `DATABASE_URL`; configure
`config.databaseUrl` for an external database instead. Kubernetes waits for the
CNPG Secret before starting the application. Environment variables are read at
startup; restart application pods after credential rotation.

This requires an application image with `DATABASE_URL` support. The generated URI
does not by itself guarantee server certificate verification; configure TLS trust
and connection settings according to your deployment requirements.

## Registration

For `registrators[]`, Required applies only when an entry is configured.

For example, this entry assigns the alias `identity` to an issuer:

```yaml
authorizationServer:
  subjectTokenIssuers:
    https://identity.example.com: identity
```

An exchanged token from this issuer contains:

```json
{
  "urn:nais:idp": "https://identity.example.com",
  "urn:nais:idp_name": "identity"
}
```

Keep the alias stable so workloads can distinguish subject-token issuers without depending on their exact URLs.
