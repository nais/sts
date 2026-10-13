# sts-operator

Kubernetes operator for STS OAuth2 client registrations. The custom resource is `STSClient` (`nais.io/v1`).

## API

```yaml
apiVersion: nais.io/v1
kind: STSClient
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

- [API types](api/nais.io/v1/sts_types.go)
- [CRD manifest](config/crd/bases/nais.io_stsclients.yaml)
- [Example resources](config/examples/sts-client-sample.yaml)

## Migration status

The operator creates application configuration in a ConfigMap named `sts-<workload>`.

Registration protocol adaptation is still pending: the operator uses `/registration/client`, expects `201 Created`, and signs the legacy software-statement payload. The repository's STS authserver uses `/v1/registration/client`, returns `200 OK`, and requires workload claims. ACL roles are not yet included in the operator's software statement. The local k3d setup uses a mock matching the operator's current protocol.

## Configuration

| Flag | Environment variable | Description |
|------|----------------------|-------------|
| `--cluster-name` | `CLUSTER_NAME` | Cluster name. |
| `--client-id` | `STS_OPERATOR_CLIENT_ID` | Operator's client ID at STS. |
| `--client-jwk-json` | `STS_OPERATOR_PRIVATE_JWK` | Operator's private key in JWK format. |
| `--sts-base-url` | `STS_URL` | STS base URL. |
| `--sts-instances` | `STS_INSTANCES` | Comma-separated STS base URLs. |
| `--auth-token-path` | `AUTH_TOKEN_PATH` | Service account token file; empty uses a client assertion. |
| `--max-concurrent-reconciles` | `STS_OPERATOR_MAX_CONCURRENT_RECONCILES` | Maximum concurrent reconciles (default `20`). |
| `--metrics-addr` | | Metrics bind address (default `:8181`). |
| `--probe-addr` | | Health probe bind address (default `:8180`). |
| `--leader-election` | | Enable leader election (default `false`). |
| `--log-level` | `LOG_LEVEL` | Log level (default `info`). |

STS authentication uses either a client assertion signed with the operator's private JWK or a service account token read from `--auth-token-path`.

### Application ConfigMap keys

- `STS_CLIENT_ID`
- `STS_WELL_KNOWN_URL`
- `STS_ISSUER`
- `STS_JWKS_URI`
- `STS_TOKEN_ENDPOINT`

The operator's private signing JWK belongs in a Secret, never an application ConfigMap. STSClient resources use finalizer `sts-operator.nais.io/finalizer`. Metrics use the `sts_client_` prefix.

## Development

Use [mise](https://mise.jdx.dev/) for the configured tools and generation tasks:

```shell
mise run generate
```

The API is a separate Go module under `api/`, referenced locally by the operator's `go.mod`.

### Run in k3d

Start Docker Desktop (or another Docker runtime), then run from `sts-operator/`:

```shell
mise install
mise run k3d
```

This creates the dedicated `sts-operator-dev` cluster, builds and imports local images, installs the CRD and RBAC, deploys mock STS and the operator, and runs a reconciliation smoke test. It generates a development signing JWK in a Kubernetes Secret. No real STS credentials or external STS service are needed.

The smoke test recreates only `sts-demo/smoke-client`, waits for its observed generation, checks the generated `sts-smoke-client` ConfigMap and owner reference, and confirms registration with the mock. The sample remains available for inspection.

```shell
mise run k3d:deploy  # rebuild and redeploy after code changes
mise run k3d:smoke   # rerun reconciliation smoke test
mise run k3d:logs    # follow operator logs
mise run k3d:down    # delete the dev cluster, including all resources and data
```

Tasks use a temporary kubeconfig and explicit context. They do not change your current Kubernetes context. The Kubernetes API binds to `127.0.0.1:6553`; set `K3D_API_PORT` before creating the cluster to use another port. To inspect resources manually:

```shell
(umask 077; k3d kubeconfig get sts-operator-dev > /tmp/sts-operator-dev.kubeconfig)
kubectl --kubeconfig=/tmp/sts-operator-dev.kubeconfig -n sts-demo get stsclients,configmaps
kubectl --kubeconfig=/tmp/sts-operator-dev.kubeconfig -n sts-operator-dev logs deployment/mock-sts
```

The mock is cluster-internal, stores registrations in memory, and does **not** authenticate requests, verify JWT signatures, enforce ACLs, or issue tokens. `/registrations` lists its current registrations. It is for controller smoke tests only, not real authentication flows. See [`config/local/`](config/local/) for manifests and [`.mise-tasks/k3d/`](.mise-tasks/k3d/) for task scripts.
