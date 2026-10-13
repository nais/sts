# Configuration

STS reads one YAML configuration file.
Set `CONFIG_FILE` to change its path; the default is `config.yaml`.
Unknown fields and multi-document YAML files are rejected.

See [`config.example.yaml`](../sts-authserver/config.example.yaml) for a local example.
It sets `tokenExpiry` to `1h` instead of the `15m` default.

| Field                                             | Default   | Required | Constraints                                                   | Description                                                                                         |
|---------------------------------------------------|-----------|----------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `bindAddress`                                     | `:8080`   |          | Nonempty.                                                     | Public HTTP listener.                                                                               |
| `internalBindAddress`                             | `:8081`   |          | Nonempty.                                                     | Internal health and metrics listener.                                                               |
| `databaseUrl`                                     |           | Yes      | Nonempty.                                                     | PostgreSQL connection URL.                                                                          |
| `encryptionKeyFile`                               |           | Yes      | Readable file containing a base64-encoded 32-byte key.        | Path to the key used to encrypt signing keys in PostgreSQL.                                         |
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

## Signing-key encryption

The key file contains a base64-encoded 32-byte key, which STS reads once at startup.
All replicas that share a database must use the same encryption key.
Local setup creates the file only when absent.

The Helm chart mounts an existing Secret named by `encryptionKeySecretName`, which defaults to `sts-encryption-key`.
Its `encryption.key` entry contains the base64 text, not the raw key bytes.
The default mount path is `/etc/sts-encryption/encryption.key`.
Provision this Secret before deployment; Helm does not generate a key.

A wrong encryption key causes startup to fail without replacing stored signing keys.
Rotation errors stop the affected process.
Request-triggered reload errors fail that request without an immediate process exit.

STS rejects existing plaintext signing keys; it does not migrate them.
For a development reset, stop all replicas before deleting the signing-key row or replacing the encryption key.
The reset invalidates existing tokens.
Keep the encryption key with database backups; key loss prevents recovery of stored signing keys.
