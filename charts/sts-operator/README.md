# sts-operator

Installs the operator that registers OAuthClient resources with STS and writes
application ConfigMaps across namespaces. Includes the
[sts-operator-crds chart](../sts-operator-crds/README.md) as a local dependency;
the operator and CRD are managed in one Helm release.

## Install

From the repository root, build the dependency and install the operator:

```shell
mise exec -- helm dependency build ./charts/sts-operator
mise exec -- helm upgrade --install sts-operator ./charts/sts-operator \
  --namespace nais-system --create-namespace \
  --set config.clusterName=dev-gcp \
  --set config.stsBaseUrl=https://sts.example.com \
  --set ingress.host=sts-operator.example.com \
  --values operator-network.yaml \
  --set image.tag=<operator-image-tag>
```

Create `operator-network.yaml` with the cluster's actual API/DNS destinations
before installing (see [Network access](#network-access)).

The image must contain the `sts-operator` binary, not the authserver. The
[operator workflow](../../.github/workflows/operator.yaml) publishes the image
and chart together; chart-only changes reuse the latest operator image.

Configure the authserver's matching `authorizationServer.environments` entry:

```yaml
name: dev-gcp
clientAuthIssuer: https://your-kubernetes-token-issuer.example.com
registrator:
  subject: system:serviceaccount:nais-system:sts-operator
  registratorJwksUri: https://sts-operator.example.com/jwks
  signingAlg: ES256
```

The subject must match the release namespace and `serviceAccount.name`.
`authToken.audience` must match `authorizationServer.expectedAudience` (default
`nais`). The chart mounts a rotating, one-hour projected service account token
for STS authentication. Kubernetes API access uses the separate, automatically
mounted service account token.

STS must be able to reach the public `/jwks` endpoint over HTTPS. The default
ingress class follows the authserver chart's `internal-haproxy` convention;
configure TLS through the ingress controller or `ingress.tls`.

## Values

See [values.yaml](values.yaml) for all defaults. Main settings:

| Value | Purpose |
|-------|---------|
| `config.clusterName` | Cluster name; replace the example value. |
| `config.stsBaseUrl` | STS issuer URL; replace the example value. |
| `config.logLevel` | Operator log level. |
| `config.maxConcurrentReconciles` | Concurrent reconciles (default `20`). |
| `authToken.audience` | Audience for the STS bearer token. |
| `authToken.expirationSeconds` | Projected token lifetime (default `3600`). |
| `serviceAccount.create` | Create an account, or use an existing account when false. |
| `serviceAccount.name` | Account used by the operator and RBAC binding. |
| `ingress.enabled` | Expose `/jwks` through an Ingress. |
| `podMonitor.enabled` | Create a PodMonitor when its API is available. |
| `fqdnNetworkPolicy.enabled` | Allow STS egress when the GKE FQDNNetworkPolicy API is available. |
| `networkPolicy.enabled` | Restrict operator egress and allow DNS/API access (default `true`). |
| `networkPolicy.apiServerCidrs` | Cluster API endpoint CIDRs allowed on TCP `443`. |
| `networkPolicy.dnsCidrs` | Additional DNS addresses allowed on UDP/TCP `53`. |
| `networkPolicy.egress` | Additional standard Kubernetes NetworkPolicy egress rules. |

The deployment deliberately uses **one replica**, **Recreate** updates and no
leader election. Signing keys are generated in memory on startup; multiple pods
behind the JWKS Service could return the wrong public key. Updates briefly
interrupt reconciliation and JWKS availability. Do not scale this deployment or
run multiple operators for the same cluster.

The chart grants cluster-wide access to OAuthClients, their status/finalizers,
ConfigMaps and events. It does not grant access to Secrets or token creation.

## Network access

The egress NetworkPolicy allows DNS pods labeled `k8s-app: kube-dns` or
`k8s-app: node-local-dns` in `kube-system` on UDP/TCP `53`. Supply DNS service/node-local IPs when pod selectors
are insufficient, and the API endpoint CIDRs required by your cluster's network
implementation (these may differ from Service IPs):

```yaml
# operator-network.yaml — replace these documentation addresses.
networkPolicy:
  apiServerCidrs: [192.0.2.1/32]
  dnsCidrs: [192.0.2.53/32]
```

**With the default empty `apiServerCidrs`, API access requires another policy to
allow it.** The chart does not allow arbitrary destinations on TCP `443`.
Use `networkPolicy.egress` for additional destinations or nonstandard API ports.

The separate FQDN policy derives the STS hostname and TCP port from
`config.stsBaseUrl` (HTTPS defaults to `443`, HTTP to `80`; explicit ports are
honored). If the GKE FQDNNetworkPolicy API is unavailable or disabled, provide an
STS allowance through `networkPolicy.egress` or another policy, or disable
`networkPolicy.enabled` for local development.

Both policies select only operator pods. They are additive with other policies
and do not restrict ingress to JWKS or metrics.

## CRD lifecycle

The local [sts-operator-crds dependency](../sts-operator-crds/README.md) places
the CRD in `templates/`, so an operator chart upgrade also updates the CRD.
Install only one operator release per cluster; do not install a separate CRD
release alongside it. Keep CRD changes compatible with existing resources and
the running operator; schema updates do not perform data migrations.

`helm rollback` can revert both the operator and CRD schema. The keep annotation
prevents removal, not updates or rollback. To revert only the operator, upgrade
using the current chart and values with an older `image.tag`.

`mise run sts-operator:generate` generates deepcopy methods and CRDs, then runs
`sts-operator:generate:chart-crds` to copy generated CRDs into
`charts/sts-operator-crds/templates/` with `helm.sh/resource-policy: keep`, then
rebuilds the dependency bundle. Edit
`sts-operator/api/nais.io/v1/oauthclient_types.go`, not the generated YAML.
Uninstalling the operator retains the CRD and OAuthClient resources, but leaves
the CRD unmanaged.
