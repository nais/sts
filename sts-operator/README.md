# sts-operator

Kubernetes operator for STS OAuth2 client registrations. The custom resource is `OAuthClient` (`nais.io/v1`).

## API

```yaml
apiVersion: nais.io/v1
kind: OAuthClient
metadata:
  name: workload-b
  namespace: team-b
spec:
  acl:
    - team: team-a
      workloads:
        - name: workload-a
          roles: [x, y]
```

An ACL lists teams and workloads allowed to access the client, with optional workload roles.

- [API types](api/nais.io/v1/oauthclient_types.go)
- [CRD manifest](config/crd/bases/nais.io_oauthclients.yaml)
- [Example resources](config/examples/oauth-client-sample.yaml)

## Migration status

The operator creates application configuration in a ConfigMap named `sts-<workload>`.

The operator uses the shared STS registration client at `/v1/registration/client` and includes ACL roles in its signed software statement.
For local development, k3d supplies Kubernetes while both Go services run on your machine.

## Configuration

| Environment variable | Description |
|----------------------|-------------|
| `CLUSTER_NAME` | Cluster name (required). |
| `STS_BASE_URL` | STS base URL (required). |
| `AUTH_TOKEN_PATH` | Bearer token file (default `/var/run/secrets/nais.io/sts/token`). |
| `LOCAL_SERVICE_ACCOUNT` | Local debugging only: request bearer tokens for `namespace/name` through the current kubeconfig instead of reading a file. |
| `MAX_CONCURRENT_RECONCILES` | Maximum concurrent reconciles (default `20`). |
| `METRICS_ADDR` | Metrics bind address (default `:8181`). |
| `PROBE_ADDR` | Health probe bind address (default `:8180`). |
| `JWKS_ADDR` | Public signing-key bind address (default `:8182`). |
| `LEADER_ELECTION` | Enable leader election (default `false`). |
| `LOG_LEVEL` | Log level (default `info`). |

By default, STS authentication uses the bearer token read from `AUTH_TOKEN_PATH`.
With `LOCAL_SERVICE_ACCOUNT` set, the registrator callback requests a fresh Kubernetes token for each registration or deletion, with audience `nais` and a one-hour lifetime.
The registration client generates an in-memory signing key for software statements and exposes its public key at `/jwks`.

### Application ConfigMap keys

- `STS_CLIENT_ID`
- `STS_WELL_KNOWN_URL`
- `STS_ISSUER`
- `STS_JWKS_URI`
- `STS_TOKEN_ENDPOINT`

Private signing keys must never appear in application ConfigMaps.
OAuthClient resources use finalizer `sts-operator.nais.io/finalizer`.
Metrics use the `oauth_client_` prefix.

## Deployment

Install the [sts-operator Helm chart](../charts/sts-operator/README.md), which
includes the [CRD chart](../charts/sts-operator-crds/README.md) as a local
dependency, cluster-wide RBAC and a public JWKS endpoint.

On pushes to `main`, `.github/workflows/operator.yaml` builds and signs changed
operator images, publishes the chart, then deploys to `ci-nais` (waiting for
completion) and `dev-nais`. Chart-only changes reuse the latest operator image.
Changes to `sts-authserver/api` also rebuild the operator because it uses that
module locally.

Image, chart, change-detection and deployment workflows are shared with the
authserver. Publishing uses the existing `gh-sts` Google service account.
Operator image releases use the `sts-operator-` tag prefix and do not replace
the repository's latest authserver release. The prefix is stripped when setting
the chart's image tag. CI versions the operator chart and its CRD dependency
together.

The operator Dockerfile uses the repository root as its build context:

```shell
docker build -f sts-operator/Dockerfile .
```

It needs the root context because `go.mod` replaces `github.com/nais/sts/api`
with `../sts-authserver/api`. The root `.dockerignore` keeps local files, `.git`
and charts out of that context.

## Development

Use [mise](https://mise.jdx.dev/) for the configured tools and generation tasks:

```shell
mise run generate
```

Generation runs in order: API deepcopy methods, CRD manifests, then
`generate:chart-crds`, which copies the generated manifests into
`charts/sts-operator-crds/templates/`, adds Helm's retention annotation, and
rebuilds the operator chart's local dependency bundle.
Change API types in `api/nais.io/v1/oauthclient_types.go`; do not edit generated
CRDs or the chart copy by hand.

The API is a separate Go module under `api/`, referenced locally by the operator's `go.mod`.

### Local debugging with k3d

Both Go services run on your machine; k3d provides only Kubernetes.
Start Docker, then run both services in the terminal from the repository root:

```shell
mise run dev
```

`dev` first runs `dev:setup`, which is safe to repeat, and then starts both services.

`dev:setup` starts PostgreSQL and the mock subject issuer, and runs `sts-operator:k3d`, which creates the cluster, installs the CRD and creates the registrator service account.
It writes a dedicated kubeconfig and CA certificate to `sts-operator/.local/` without changing your default Kubernetes context.
The API listens on `127.0.0.1:6553` and is the token issuer.
Set `K3D_API_PORT` before cluster creation to change the port, and update `clientAuthIssuer` in `config.k3d.yaml` to match.

IntelliJ skips Mise, so run `mise run dev:setup` first, then open the repository root and run or debug `STS Local` from `.run/`.
Use one or the other; both bind the same ports.

The operator runs `cmd/sts-operator-local`, which requests service account tokens through the kubeconfig; production uses `cmd/sts-operator`.
The authserver trusts the k3d CA through `additionalCAFile`.
Endpoints:

- Authserver: `http://localhost:8080`
- Operator JWKS: `http://localhost:8182/jwks`

Apply and inspect sample clients from `sts-operator/`:

```shell
mise run k3d:sample
kubectl --kubeconfig=.local/kubeconfig -n sts-demo get oauthclients,configmaps
```

Delete only the development cluster when finished:

```shell
mise run sts-operator:k3d:down
```
