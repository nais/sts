-- name: GetKubernetesClient :one
SELECT *
FROM kubernetes_clients
WHERE id = @client_id;

--- name: ListClientAccess :many
-- SELECT sqlc.embed(clients), client_access.roles
-- FROM client_access
--          JOIN clients ON clients.id = client_access.target_id
-- WHERE client_access.client_id = $1
-- ORDER BY clients.id;

-- name: UpsertKubernetesClient :exec
INSERT INTO kubernetes_clients (id, environment, namespace, workload, issuers)
VALUES (@id, @environment, @namespace, @workload, @issuers::TEXT[])
ON CONFLICT (id) DO UPDATE SET issuers  = EXCLUDED.issuers,
                               updated_at       = NOW();

-- name: UpsertAuthorizationPolicy :exec
INSERT INTO authorization_policies (owner_client_id, consumer_client_id, roles)
VALUES (@owner_client_id, @consumer_client_id, @roles::TEXT[])
ON CONFLICT (owner_client_id, consumer_client_id) DO UPDATE SET roles = EXCLUDED.roles;
