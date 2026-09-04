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

Use [mise](https://mise.jdx.dev/):

```shell
mise tasks
```

Start the service locally:

```shell
mise run local
```

Server runs two listeners for public and internal use:

- `http://localhost:8080/.well-known/oauth-authorization-server`
- `http://localhost:8081/healthz`
- `http://localhost:8081/readyz`
- `http://localhost:8081/metrics`

Edit `.env` to override the local configuration.
