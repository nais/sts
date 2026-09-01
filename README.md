# sts

Nais Security Token Service (STS) is an OAuth 2.1 authorization server for
workloads running on Nais.

STS issues short-lived security tokens for exactly one audience. Callers must be:

- authenticated with workload identity assertions and
- be granted access through audience's access rules

The service will support:

- [RFC 6749 Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) for machine-to-machine access
- [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) for on-behalf-of flows

## Development

Install the pinned tools and run the checks with [mise](https://mise.jdx.dev/):

```shell
mise run setup
mise install
mise run test
mise run test:integration
mise run check
```

Start the service locally:

```shell
mise run database:up
mise run local
```

The public listener uses `http://localhost:8080`.

The internal listener uses `http://localhost:8081` and serves `/healthz`, `/readyz`, and `/metrics`.

Edit `.env` to override the local configuration.

### Request tokens

The token tasks require `kubectl` access to the development cluster in the
`dev-nais` tenant. Configure `CLIENT_ID`, `WORKLOAD_NAME`, and `TOKEN_AUDIENCE`
in `.env`.

```shell
mise run token:m2m
mise run token:obo
```

Both tasks create a workload identity token from the active Kubernetes context
and namespace. The OBO task also uses it as the subject token.

## Helm

Render the chart locally:

```shell
helm template sts ./charts
```

The workflow publishes the image and chart from `main`.
