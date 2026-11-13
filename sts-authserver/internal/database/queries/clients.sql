-- name: GetClient :one
SELECT
	*
FROM
	clients
WHERE
	issuer = @issuer
	AND namespace = @namespace
	AND name = @name;

-- name: GetClientByIDForUpdate :one
SELECT
	*
FROM
	clients
WHERE
	id = @id
FOR UPDATE;

-- name: DeleteClient :exec
DELETE FROM clients
WHERE id = @id;

-- name: ListClients :many
SELECT
	*
FROM
	clients
ORDER BY
	id;

-- name: UpsertClient :one
INSERT INTO clients(
	id,
	environment,
	namespace,
	name,
	issuer,
	authorization_policy)
VALUES (
	@id,
	@environment,
	@namespace,
	@name,
	@issuer,
	@authorization_policy::JSONB)
ON CONFLICT (
	id)
	DO UPDATE SET
		authorization_policy = EXCLUDED.authorization_policy,
		issuer = EXCLUDED.issuer,
		updated_at = NOW()
	WHERE
		clients.environment = EXCLUDED.environment
		AND clients.namespace = EXCLUDED.namespace
		AND clients.name = EXCLUDED.name
		AND (
			clients.authorization_policy IS DISTINCT FROM EXCLUDED.authorization_policy
			OR clients.issuer IS DISTINCT FROM EXCLUDED.issuer)
	RETURNING
		*;

