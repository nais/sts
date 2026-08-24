# sts

OAuth 2.0 authorization server for NAIS.

This repository currently provides the service and deployment scaffold. OAuth
grants, client storage, authentication, signing keys, and token persistence are
not implemented.

## Development

Install the pinned tools and run the checks with [mise](https://mise.jdx.dev/):

```shell
mise install
mise run test
mise run check
```

Start the service locally:

```shell
go run ./cmd/sts
```

The public listener uses `http://localhost:8080`. The internal listener uses
`http://localhost:8081` and serves `/healthz`, `/readyz`, and `/metrics`.

Configuration uses environment variables. Set the external issuer when the
public URL differs from the local default:

```shell
ISSUER=https://sts.example.com go run ./cmd/sts
```

The available variables are `BIND_ADDRESS`, `INTERNAL_BIND_ADDRESS`, `ISSUER`,
and `LOG_LEVEL`.

## Helm

Render the chart locally:

```shell
helm template sts ./charts
```

The workflow publishes the image and chart from `main`. Automatic Fasit
deployment is intentionally disabled.
