# Architecture

STS separates public token and registration traffic from internal health checks and metrics.

## HTTP listeners

| Listener                         | Routes                                                                                  | Purpose                                                   |
|----------------------------------|-----------------------------------------------------------------------------------------|-----------------------------------------------------------|
| Public (`bindAddress`)           | `/.well-known/oauth-authorization-server`, `/token`, `/jwks`, `/v1/registration/client` | Discovery, token requests, public keys, and registration. |
| Internal (`internalBindAddress`) | `/healthz`, `/readyz`, `/metrics`                                                       | Health checks and Prometheus metrics.                     |

`/healthz` returns `ok` without checking PostgreSQL.
`/readyz` checks PostgreSQL.

## Token issuance

For each token request, STS:

1. Verifies the client's workload identity token.
2. Checks the client's authorization policy for the target.
3. Issues an access token for that target.

Token exchange also verifies a subject token.

See [Client usage](usage.md) for requests and responses.

## PostgreSQL and caches

PostgreSQL stores registrations, policies, and signing keys.
Each pod keeps a snapshot of clients and policies for token requests.

Notifications and periodic refreshes update the snapshot.
On a cache miss, STS queries PostgreSQL.

STS applies database migrations at startup.
It creates signing keys for a fresh database and rotates them when they expire.

`/jwks` serves the public keys.

See [ADR 0001](adr/0001-cache-client-registrations-in-snapshots.md) for the cache decision and its limits.
