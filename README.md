# nais-sts

Nais Security Token Service (STS) is an OAuth 2.1 authorization server for
Kubernetes workloads running on Nais.

STS issues short-lived access tokens to clients for exactly one target audience.
Clients must authenticate with workload identity assertions and have access through an authorization policy.

The service supports:

- [RFC 6749 Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) for machine-to-machine access
- [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) for on-behalf-of flows when subject-token issuers are configured

## How it works

```text
              Kubernetes API server (workload issuer)
                    /                      \
  issues identity token                issues identity token
                ▼                            ▼
          Registrator                     Client
                │                            │
 registers clients and policies    requests or exchanges token
                │                   with identity token
                └──────────► STS ◄───────────┘
                             │
                         issues token
                             ▼
                           Client ── presents token ──► Target
```

1. The **Kubernetes API server** acts as the workload issuer. It issues projected
   service account tokens that workloads use to authenticate with STS.
2. A **registrator** registers clients and their authorization policies with
   STS. It can register clients only for its configured workload issuer.
3. A **client** is a registered Kubernetes workload that requests tokens. It
   acts as an OAuth [client](https://www.rfc-editor.org/rfc/rfc6749#section-1.1).
4. An **authorization policy** states which target a client can request and
   which roles its token receives.
5. **STS** authenticates the client, checks its policy, and issues a token for
   one target. Token exchange also requires a subject token from an accepted issuer.
6. A **target** is the intended audience of the token. The receiving service
   validates the token before accepting it.

## Documentation

- [Architecture](docs/architecture.md): components, project layout, request flows, and storage
- [Configuration](docs/configuration.md): YAML settings and deployment values
- [Client registration](docs/registration.md): register clients and policies
- [Client usage](docs/usage.md): request tokens with client credentials or token exchange
- [Benchmarks](docs/benchmarks.md): run and interpret local benchmarks

## Local development

Install [mise](https://mise.jdx.dev/).
Run the commands in this section from the repository root:

```shell
mise run local
```

Endpoints:

- http://localhost:8080/.well-known/oauth-authorization-server
- http://localhost:8081/healthz
- http://localhost:8081/readyz
- http://localhost:8081/metrics

Try the token flows:

- `mise run sts-authserver:token:m2m`: get a client credentials token.
- `mise run sts-authserver:token:obo`: exchange a subject token.

Configuration:

- Local setup copies `sts-authserver/config.example.yaml` to the gitignored `sts-authserver/config.yaml` if absent.
- Edit `sts-authserver/config.yaml` for local settings. See [configuration](docs/configuration.md).

Run `mise tasks --all` for all commands.
