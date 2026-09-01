-- name: GetKubernetesClient :one
SELECT *
FROM kubernetes_clients
WHERE id = @client_id;

-- name: GetAuthorizationPolicy :one
SELECT *
FROM authorization_policies
WHERE owner_client_id = @owner_client_id
  AND consumer_client_id = @consumer_client_id;

-- name: UpsertKubernetesClient :exec
INSERT INTO kubernetes_clients (id, environment, namespace, workload, issuers, allowed_scopes)
VALUES (@id, @environment, @namespace, @workload, @issuers::TEXT[], @allowed_scopes::TEXT[]) ON CONFLICT (id) DO
UPDATE SET issuers = EXCLUDED.issuers,
    updated_at = NOW();

-- name: UpsertAuthorizationPolicy :exec
INSERT INTO authorization_policies (owner_client_id, consumer_client_id, roles)
VALUES (@owner_client_id, @consumer_client_id, @roles::TEXT[]) ON CONFLICT (owner_client_id, consumer_client_id) DO
UPDATE SET roles = EXCLUDED.roles;
