-- name: GetKubernetesClient :one
SELECT *
FROM kubernetes_clients
WHERE issuer = @issuer
  AND namespace = @namespace
  AND workload = @workload;

-- name: GetAuthorizationPolicy :one
SELECT *
FROM authorization_policies
WHERE owner_client_id = @owner_client_id
  AND consumer_client_id = @consumer_client_id;

-- name: ListKubernetesClients :many
SELECT *
FROM kubernetes_clients
ORDER BY id;

-- name: ListAuthorizationPolicies :many
SELECT *
FROM authorization_policies
ORDER BY owner_client_id, consumer_client_id;

-- name: UpsertKubernetesClient :exec
INSERT INTO kubernetes_clients (id, environment, namespace, workload, issuer, allowed_scopes)
VALUES (@id, @environment, @namespace, @workload, @issuer, @allowed_scopes::TEXT[]) ON CONFLICT (id) DO
UPDATE SET allowed_scopes = EXCLUDED.allowed_scopes,
    updated_at = NOW();

-- name: UpsertAuthorizationPolicy :exec
INSERT INTO authorization_policies (owner_client_id, consumer_client_id, roles)
VALUES (@owner_client_id, @consumer_client_id, @roles::TEXT[]) ON CONFLICT (owner_client_id, consumer_client_id) DO
UPDATE SET roles = EXCLUDED.roles;
