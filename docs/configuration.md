# Configuration

`sts.LoadConfig()` reads one YAML configuration file into `sts.Config`.
Set `CONFIG_FILE` to change its path; the default is `config.yaml`.
Unknown fields and multi-document YAML files are rejected.
Defaults are declared with `default:"..."` Go struct tags and applied before YAML
is decoded, including each environment entry. Explicit empty strings and zero durations are not replaced with defaults;
they are rejected where validation requires nonempty or positive values.
Programmatic callers and tests can start with `oauth.DefaultAuthorizationServerConfig()`
and then assign required fields and overrides. Plain struct literals do not apply defaults.
For programmatically added environments, set `ClientAuthIssuerAlias` explicitly or
call `config.Apply(&env)` before assigning overrides. The shared helper lives in
`internal/config`; the loader and its tests live in `internal/sts`.
A nonempty `DATABASE_URL` environment variable overrides the file's `databaseUrl`
before validation. Otherwise, `databaseUrl` must be supplied in the file.

See [`config.example.yaml`](../sts-authserver/config.example.yaml) for a local example.
It sets `tokenExpiry` to `1h` instead of the `15m` default.

The Helm chart's `config` values map verbatim to this file's fields.
`environments[].registrator.signingAlg` sets the algorithm the registrator must use to sign software statements.

| Field                                             | Default   | Required | Constraints                                                   | Description                                                                                    |
|---------------------------------------------------|-----------|----------|---------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `bindAddress`                                     | `:8080`   |          | Nonempty.                                                     | Public HTTP listener.                                                                          |
| `internalBindAddress`                             | `:8081`   |          | Nonempty.                                                     | Internal health and metrics listener.                                                          |
| `databaseUrl`                                     |           | Yes      | Nonempty unless supplied through `DATABASE_URL`.              | PostgreSQL connection URL; overridden by nonempty `DATABASE_URL`.                              |
| `logLevel`                                        | `info`    |          |                                                               | Log level.                                                                                     |
| `logFormat`                                       | `text`    |          | `text` or `json`.                                             | Log format.                                                                                    |
| `additionalCAFile`                                | empty     |          | Path to a PEM file, or empty.                                 | Supplements system roots for local k3d. Upstream TLS verification stays enabled.               |
| `authorizationServer.issuer`                      |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | STS issuer URL.                                                                                |
| `authorizationServer.expectedAudience`            | `nais`    |          | Nonempty.                                                     | Sole audience for client assertions and registration bearer tokens.                            |
| `authorizationServer.externalIssuers`             | `{}`      |          | Must not reuse an environment issuer or alias.                 | External subject-token aliases mapped to issuer URLs.                                         |
| `authorizationServer.maxClientAuthTokenLifetime`  | `1h`      |          | Positive duration.                                            | Maximum client assertion and registration bearer-token lifetime, plus one minute of tolerance. |
| `authorizationServer.tokenExpiry`                 | `15m`     |          | Positive duration.                                            | Lifetime of access tokens issued by STS.                                                       |
| `authorizationServer.environments`                |           | Yes      | At least one entry.                                           | Kubernetes clusters whose workloads can register and authenticate.                             |
| `environments[].name`                             |           | Yes      | Unique lowercase name.                                        | Human-readable alias for the cluster issuer; the first part of every client ID in the cluster. |
| `environments[].clientAuthIssuer`                 |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | Issuer of the cluster's client assertions and registration bearer tokens.                      |
| `environments[].clientAuthIssuerAlias`            | `kubernetes` |       | Nonempty; must not overlap an external issuer alias.          | Alias assigned to subject tokens from this environment.                                      |
| `environments[].registrator.subject`              |           | Yes      | Nonempty.                                                     | Subject of the registrator's bearer token.                                                     |
| `environments[].registrator.registratorJwksUri`   |           | Yes      | HTTPS, or HTTP on localhost/loopback.                         | URL of the public keys used to verify software statements.                                     |
| `environments[].registrator.signingAlg`           |           | Yes      | RS256/384/512, PS256/384/512, or ES256/384/512.               | Required software-statement signing algorithm.                                                 |

## Helm database credentials

The authserver chart depends on [`nais-postgresql`](https://github.com/nais/helm-charts/tree/main/charts/nais-postgresql), published from `nais/helm-charts`.
Its dependency alias is `postgresql`, so configure it under that values key.
After changing the dependency version, run `helm dependency update charts/sts-authserver` and commit `Chart.lock`.
The selected version must be published before STS can build its dependencies.

With `postgresqlEnabled: true`, the authserver chart sets `DATABASE_URL` from the
CNPG-generated application's Secret (`<cluster-name>-app`, key `uri`). The Secret
name is built directly from `postgresql.fullnameOverride`, which defaults to
`sts-postgresql`. This value is required when the dependency is enabled and must
be a valid Cluster name of at most 50 characters. The parent does not call the
subchart's naming helper. No database password is copied into the configuration
Secret or Helm values.

`postgresql.fullnameOverride` identifies the database Cluster. Multiple releases
in the same namespace need distinct overrides.

With `postgresqlEnabled: false`, the chart does not set `DATABASE_URL`; configure
`config.databaseUrl` for an external database instead. Kubernetes waits for the
CNPG Secret before starting the application. Environment variables are read at
startup; restart application pods after credential rotation.

The generated URI does not by itself guarantee server certificate verification;
configure TLS trust and connection settings according to your deployment requirements.

## Environments

Client IDs have the form `environment:namespace:name`.
Renaming an environment, or moving its name to another issuer, changes or conflicts with existing client IDs.
Treat both as stable once clients are registered.

Registration expands every authorization policy into one row per configured environment.
After adding or removing an environment, re-register every client to regenerate its policies.

## Subject token issuers

STS accepts subject tokens from the environments' Kubernetes issuers. Each environment
sets `clientAuthIssuerAlias`, which defaults to `kubernetes`. Environments may share
an issuer and alias; use the same alias when sharing an issuer.
Configure external issuers in `externalIssuers` with aliases as keys and issuer URLs
as values; they must not reuse any environment issuer URL or alias.

For example, this entry assigns the alias `identity` to an issuer:

```yaml
authorizationServer:
  externalIssuers:
    identity: https://identity.example.com
```

An exchanged token from this issuer contains:

```json
{
  "urn:nais:idp": "https://identity.example.com",
  "urn:nais:idp_alias": "identity"
}
```

Keep the alias stable so workloads can distinguish subject-token issuers without depending on their exact URLs.
Chained STS exchanges retain the original `urn:nais:idp` and `urn:nais:idp_alias`.
