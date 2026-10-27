# Branch deployments

Push to a `deploy/*` branch to deploy changed components to **dev-nais**:

```shell
git push origin HEAD:deploy/my-test
```

The workflow compares the branch with its merge-base on `main`:

| Changed paths | Deploys |
| --- | --- |
| `sts-authserver/`, `charts/sts-authserver/` | authserver |
| `sts-operator/`, `sts-authserver/api/`, `charts/sts-operator*/` | operator |

A component deploys only if its chart exists on the branch. Each selected
component is checked, built, packaged with that image as chart version
`0.0.0-branch.<sha>.<run>.<attempt>` and deployed to dev-nais. No GitHub release
is created, so main never picks up branch images.

Caveats:

- Every push redeploys all components changed on the branch, not just the last commit.
- Branch deployments replace the shared dev-nais services; main deployments replace them back.
- Deleting the branch does not roll back.

## Required settings

- **Ruleset** targeting `deploy/*`: restrict creations and updates; bypass only for
  the maintainer team. This limits deployments to maintainers.
- **Environment** `sts-deploy-dev`: deployment branches limited to `deploy/*`, no
  required reviewers.
- **Google workload identity and Fasit** must trust jobs in `sts-deploy-dev`
  (OIDC subject `repo:nais/sts:environment:sts-deploy-dev`).
