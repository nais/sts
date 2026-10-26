# sts-operator-crds

Defines the `OAuthClient` CRD (`oauthclients.nais.io`). Included as a local
`file://` dependency of the [operator chart](../sts-operator/README.md), so the
operator and CRD share one release. The chart has no configurable values.

## Install and upgrade

Install and upgrade through the [operator chart](../sts-operator/README.md).
Do not install a standalone CRD release alongside it: the same CRD cannot be
owned by both releases. Install only one operator release per cluster.

CRDs live in `templates/`, so Helm applies schema updates during operator chart
upgrades, unlike files in `crds/`. Keep schema changes compatible with the
running operator and existing resources.

The checked-in chart and dependency versions are development placeholders.
When packaging for CI, `ci:package-chart` assigns the generated release version
to both charts and the dependency pin, then refreshes the lock and bundle.
No manual version bump or separate CRD publication is needed.

Helm updates the CRD definition; it does not migrate stored objects. Incompatible
field changes or stored-version changes need a staged migration and may require
a conversion webhook. A Helm rollback does not reverse data migrations, and
rolling back a CRD schema may be unsafe after newer objects have been stored.

## Generation

The API types are the source of truth:
`sts-operator/api/nais.io/v1/oauthclient_types.go`.

```shell
mise run sts-operator:generate
```

This generates deepcopy methods and CRDs under `sts-operator/config/crd/bases/`,
then runs `sts-operator:generate:chart-crds` to copy them into this chart's
`templates/` directory, add `helm.sh/resource-policy: keep`, and rebuild the
operator chart's dependency bundle. Do not edit the generated YAML by hand.

## Retention

The keep annotation tells Helm to retain the CRD when an uninstall or upgrade
would otherwise remove it. It does not prevent schema updates or rollback.

**Deleting the CRD directly also deletes all OAuthClient resources in the cluster.**
The annotation does not protect against direct Kubernetes deletion.

Uninstalling the operator release leaves the CRD behind and unmanaged.
Reinstalling under a different release name or namespace requires deliberate
ownership adoption.
