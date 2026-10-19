# postgresql

Minimal PostgreSQL chart using `postgresql.cnpg.io/v1`. Creates one CloudNativePG
`Cluster`, not the operator or its CRDs. CNPG manages pods, PVCs, services, TLS,
failover, and application credentials.

**Not production-ready yet: backups and recovery are not configured.**

## Prerequisites

- A running CloudNativePG operator and its CRDs, with support for PostgreSQL 18
  and the fields used by this chart. Check the installed operator's support matrix.
- A default StorageClass, or set `storage.storageClass` explicitly. Check that it
  supports volume expansion and works with your cluster's node/zone layout.
- Three eligible nodes for the default required pod anti-affinity. Insufficient
  nodes leave replicas Pending rather than placing them together.
- Namespace policies allowing CNPG reconciliation, replication, monitoring, and
  application connections. Optional NetworkPolicy support is disabled by default;
  configure it for your platform before enabling it (see below).

## Install

From the repository root:

```sh
mise exec -- helm lint --strict charts/postgresql
mise exec -- helm template example charts/postgresql \
  --namespace application --set fullnameOverride=example-db
mise exec -- helm upgrade --install example charts/postgresql \
  --namespace application --set fullnameOverride=example-db
kubectl get clusters.postgresql.cnpg.io -n application example-db
```

Use a stable `fullnameOverride` and namespace. Names without an override default
to `<release>-postgresql` (unless the release already contains the chart name).
Changing the name creates a different database cluster; it does not rename or
migrate the existing one. Do not adopt an existing Cluster without reviewing
Helm ownership and migration.

Defaults:

| Value | Default | Purpose |
| --- | --- | --- |
| `instances` | `3` | Total instances: one primary, two replicas |
| `imageName` | `ghcr.io/cloudnative-pg/postgresql:18` | PostgreSQL image; pin a tested patch/digest for production |
| `database.name` / `database.owner` | `app` / `app` | Initial database and non-superuser owner |
| `storage.size` | `10Gi` | Data volume size **per instance**, at least 30Gi total |
| `storage.storageClass` | `""` | Omit field and use the cluster default |
| `resources.requests` | `100m` CPU / `256Mi` memory | Per-instance starting point; load-test and tune |
| `resources.limits` | `512Mi` memory | Per instance; no CPU limit by default |
| `affinity.podAntiAffinityType` | `required` | Spread instances across nodes |
| `keep` | `true` | Retain Cluster on Helm uninstall |
| `postgresql.parameters` | `{}` | PostgreSQL parameters; quote all values |

For a single-node development cluster:

```sh
mise exec -- helm template dev charts/postgresql --set instances=1
```

`database.name` and `database.owner` apply only during initial bootstrap. Changing
these values does not rename existing roles/databases or rotate credentials.
Superuser password access is disabled. The application owner can manage its own
database (including migrations); it is not a separate least-privileged runtime role.

## Use as a dependency

For a sibling application chart, add this to its `Chart.yaml`:

```yaml
dependencies:
  - name: postgresql
    alias: postgresql
    version: "0.1.0"
    repository: "file://../postgresql"
    condition: postgresqlEnabled
```

Configure it in the **parent** chart's `values.yaml`:

```yaml
postgresqlEnabled: true
postgresql:
  instances: 3
  database:
    name: example
    owner: example
  storage:
    size: 20Gi
    storageClass: ""
```

Run `mise exec -- helm dependency update charts/<parent-chart>` after adding the
dependency. Helm vendors the dependency into the parent chart; follow the parent
chart's policy for committing `Chart.lock` and packaged dependencies.

With alias `postgresql`, a release named `example` creates `example-postgresql`.
All chart settings can be overridden under the alias, including `fullnameOverride`
when the parent needs an explicit connection target. The namespace comes from the
parent release. Multiple aliases can deploy separate databases with distinct names.
`postgresqlEnabled` is a parent-only dependency condition, not a setting inside
this chart. Helm parent `global` values are accepted but not used; configure this chart explicitly
under its dependency key. Helpers remain namespaced as `postgresql.*` regardless of alias.

The parent application chart must reference the generated Secret; adding this
dependency does not automatically configure the application's database connection.
Never put application-specific names or credentials in the dependency's defaults.

## Application connection

For a Cluster named `example-db`:

- Primary service: `example-db-rw:5432` in the same namespace, or
  `example-db-rw.application.svc:5432` across namespaces.
- CNPG-generated Secret: `example-db-app`, including `username`, `password`, `dbname`,
  and `uri` keys. Reference it from the application via `secretKeyRef` or a volume.
  Secrets are namespace-scoped; an application in another namespace needs an
  explicit, approved credential distribution mechanism.
- CNPG manages server TLS. Configure clients to verify the server certificate
  (`sslmode=verify-full`) using CNPG's CA and the matching service DNS name.
  Do not assume the generated URI enforces certificate verification.

### Stable generated Secret name from a parent chart

Keep CNPG in charge of credential generation and set a stable Cluster name in the
parent's values (using the dependency alias):

```yaml
postgresql:
  fullnameOverride: example-db
```

The generated Secret is then `example-db-app`. An application Deployment in the
same namespace can consume it directly:

```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: example-db-app
        key: uri
```

The generated Secret name cannot be configured independently of the Cluster name.
`bootstrap.initdb.secret.name` would reference an existing credentials Secret,
not rename the generated one. Choose `fullnameOverride` before the first install;
changing it on an existing deployment creates a different Cluster, not a Secret rename.
Use distinct names for separate installations in the same namespace.

Use the application's supported Secret reference mechanism. Avoid copying a
plaintext connection URL into committed values files or Helm release values.

## Network policy

`networkPolicy.enabled: true` creates a database-pod policy using
`cnpg.io/cluster: <cluster-name>`, including matching initdb/job pods. It permits
same-cluster ingress and egress on all ports. Standard rules are built in;
configure them through values in the parent chart:

```yaml
postgresql:
  networkPolicy:
    enabled: true
    apiServerCidrs: [192.0.2.1/32] # Example only; replace with your API endpoint.
    dnsCidrs: [192.0.2.53/32] # Example only; replace with your DNS address.
    operator:
      name: cloudnative-pg
      namespace: nais-system
```

- Application access always matches `app.kubernetes.io/instance` to `.Release.Name`
  and permits TCP 5432 from same-release pods in the database namespace. Parent
  and subchart share the release name; no application name setting is needed.
- `operator.name` matches `app.kubernetes.io/name`, not a Kubernetes resource name.
  Defaults are `cloudnative-pg` in `nais-system`.
  Operator access permits TCP 8000; verify these selectors/ports in your cluster.
- `apiServerCidrs` allows TCP 443 to the listed API endpoint CIDRs. Set the actual
  endpoint address required by your CNI; it may differ from the Kubernetes Service IP.
- DNS egress allows kube-dns and node-local-dns pods in `kube-system` on UDP/TCP 53.
  `dnsCidrs` adds IP-based destinations for DNS Service or node-local addresses.
  Bare pod selectors would only match DNS pods in the database namespace.
- Both CIDR lists default to empty. The example addresses above use the reserved
  documentation range `192.0.2.0/24`; replace them with your cluster's addresses.
  These rules select database pods **and initdb jobs** through the cluster label.

Additional `networkPolicy.ingress` and `networkPolicy.egress` lists accept standard
Kubernetes rules for cross-namespace clients, alternative selectors/ports,
monitoring (typically TCP 9187), backups, and plugins. Standard rules are additive;
these extra lists do not replace them.

Authserver enables the policy and supplies its API/DNS CIDRs, relying on the
operator defaults. Existing namespace policies remain additive.

NetworkPolicies are additive, so existing broad policies may still allow more
traffic than this chart lists. This chart does not configure
application egress: if the application is egress-isolated, its policies must also
allow the database, DNS, and any external issuers it uses.

`keep` retains only the Cluster, not this NetworkPolicy. A Helm uninstall removes
the chart-managed policy; review remaining platform policies for retained databases.

## Before production

1. **Backups and recovery:** choose object storage, workload identity, retention,
   encryption, and backup tooling compatible with your installed CNPG/operator
   plugins. Configure base backups plus continuous WAL archiving for point-in-time
   recovery. Define RPO/RTO, alert on backup/WAL failures, and test restores into a
   separate cluster. Replicas do not protect against accidental deletion or corruption.
2. **Availability:** defaults use asynchronous replication; failover can lose recent
   commits. Decide whether synchronous replication is required and its availability
   trade-off before extending this chart. Node spreading is not zone spreading;
   plan zone placement and storage behavior for a zone failure.
3. **Capacity:** measure CPU, memory, connections, data and WAL growth. Set appropriate
   requests/limits, disk headroom, and PostgreSQL parameters. Consider pooling if
   connection counts warrant it. Never shrink a volume through values.
4. **Monitoring:** integrate CNPG metrics with the platform's scraping setup and
   alert on unavailable primaries, replication lag, disk pressure, restarts, failed
   reconciliations, and backup age. Monitoring resources are not created here.
5. **Security:** verify platform network/admission policy compatibility, restrict Secret
   access, enforce client TLS verification, and decide whether migrations and runtime
   should use separate roles. No public service or ingress is created.
6. **Maintenance:** pin an approved image patch/digest; plan minor updates, switchover,
   maintenance disruption, and major upgrades. A Helm image change is not a major
   upgrade strategy. Validate against the installed CRD/admission webhooks in staging.

## Deletion and recovery

By default, `helm.sh/resource-policy: keep` retains the Cluster on uninstall.
The operator and database continue running and consuming resources. A later
install with the same name can conflict with the retained resource; review Helm
ownership and an explicit adoption plan before reinstalling. Retention is not a
backup and does not prevent direct Cluster deletion or namespace deletion.

To deliberately enable deletion through Helm, first upgrade the existing release
with `--set keep=false`, verify that the annotation is gone, then uninstall.
Review CNPG PVC ownership and the StorageClass reclaim policy first: deletion may
permanently destroy data, or leave billable volumes. Do not rely on PVC retention
for recovery.

## Checks

From the repository root:

```sh
mise run check:helm-lint
mise run check:postgresql
```

Render tests check defaults, overrides, and invalid values. They do not validate
against a live CNPG CRD. Before deployment, run `kubectl apply --dry-run=server`
on rendered manifests in the target environment to check CRDs and admission policies.
