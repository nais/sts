# nais-sts

Nais Security Token Service (STS) is an OAuth 2.1 authorization server for
Kubernetes workloads running on Nais.

STS issues short-lived access tokens to clients for exactly one target audience.
Clients must authenticate with workload identity assertions and have access through an authorization policy.

The service supports:

- [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) for exchanging Kubernetes service account tokens or tokens from configured external issuers

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
   one target. Token exchange requires a subject token from an accepted issuer.
6. A **target** is the intended audience of the token. The receiving service
   validates the token before accepting it.

## Documentation

- [Architecture](docs/architecture.md): components, project layout, request flows, and storage
- [Configuration](docs/configuration.md): YAML settings and deployment values
- [Branch deployments](docs/deployment.md): automatic dev-nais deployments from protected branches
- [Client registration](docs/registration.md): register clients and policies
- [Client usage](docs/usage.md): request tokens with token exchange
- [Benchmarks](docs/benchmarks.md): run and interpret local benchmarks

## Local development

Install [mise](https://mise.jdx.dev/) and start Docker.
Run the commands in this section from the repository root.

### Full stack on k3d

```shell
mise run dev  # prepares k3d and PostgreSQL, then runs authserver and operator
```

For IntelliJ, run `mise run dev:setup` first, then run "STS Local".

Setup installs the sample workloads. Once the operator registers both sample clients, run
`mise run dev:token` to exchange the workload's own service account token.

See the [operator README](sts-operator/README.md#local-debugging-with-k3d) for details.

### Standalone authserver with mock services

```shell
mise run sts-authserver:dev  # starts Docker mock services, seeds fixtures, runs authserver
```

This starts PostgreSQL and a mock OAuth server in Docker, seeds fixtures and runs the authserver with `sts-authserver/config.yaml`, copied from `config.example.yaml` if absent.
Add `--k3d` to prepare the k3d environment and run only the authserver against it.
It uses the same ports as the k3d workflow, so run only one at a time.

Endpoints:

- http://localhost:8080/.well-known/oauth-authorization-server
- http://localhost:8081/healthz
- http://localhost:8081/readyz
- http://localhost:8081/metrics

Try token exchange:
- `mise run sts-authserver:dev:token`: exchange the workload's own service account token against the standalone mock setup. Add `--k3d` to target the full k3d stack instead.
- Add `--exchange` to either form to exchange a subject token from the mock external issuer instead.

Run `mise tasks --all` for all commands.
