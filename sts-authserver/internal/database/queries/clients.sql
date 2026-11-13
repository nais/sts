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

-- name: GetAuthorizationPolicy :one
SELECT
	*
FROM
	authorization_policies
WHERE
	owner_client_id = @owner_client_id
	AND consumer_client_id = @consumer_client_id;

-- name: ListClients :many
SELECT
	*
FROM
	clients
ORDER BY
	id;

-- name: ListAuthorizationPolicies :many
SELECT
	*
FROM
	authorization_policies
ORDER BY
	owner_client_id,
	consumer_client_id;

-- name: ListAuthorizationPoliciesByOwner :many
SELECT
	*
FROM
	authorization_policies
WHERE
	owner_client_id = @owner_client_id
ORDER BY
	owner_client_id,
	consumer_client_id;

-- name: UpsertClient :one
INSERT INTO clients(
	id,
	environment,
	namespace,
	name,
	issuer,
	allowed_scopes,
	allow_all_consumers,
	allowed_consumer_namespaces)
VALUES (
	@id,
	@environment,
	@namespace,
	@name,
	@issuer,
	@allowed_scopes::TEXT[],
	@allow_all_consumers,
	COALESCE(
		@allowed_consumer_namespaces::TEXT[], '{}'))
ON CONFLICT (
	id)
	DO UPDATE SET
		allowed_scopes = EXCLUDED.allowed_scopes,
		allow_all_consumers = EXCLUDED.allow_all_consumers,
		allowed_consumer_namespaces = EXCLUDED.allowed_consumer_namespaces,
		issuer = EXCLUDED.issuer,
		updated_at = NOW()
	WHERE
		clients.environment = EXCLUDED.environment
		AND clients.namespace = EXCLUDED.namespace
		AND clients.name = EXCLUDED.name
		AND (
			clients.allowed_scopes IS DISTINCT FROM EXCLUDED.allowed_scopes
			OR clients.allow_all_consumers IS DISTINCT FROM EXCLUDED.allow_all_consumers
			OR clients.allowed_consumer_namespaces IS DISTINCT FROM EXCLUDED.allowed_consumer_namespaces
			OR clients.issuer IS DISTINCT FROM EXCLUDED.issuer)
	RETURNING
		*;

-- name: DeleteAuthorizationPolicies :exec
DELETE FROM authorization_policies
WHERE owner_client_id = @owner_client_id;

-- name: DeleteOrphanedAuthorizationPolicies :exec
DELETE FROM authorization_policies
WHERE owner_client_id = @owner_client_id
	AND consumer_client_id = ANY (@orphaned_ids::TEXT[]);

-- name: BatchUpsertAuthorizationPolicy :batchexec
INSERT INTO authorization_policies(
	owner_client_id,
	consumer_client_id,
	roles)
VALUES (
	@owner_client_id,
	@consumer_client_id,
	@roles::TEXT[])
ON CONFLICT (
	owner_client_id,
	consumer_client_id)
	DO UPDATE SET
		roles = EXCLUDED.roles
	WHERE
		authorization_policies.roles IS DISTINCT FROM EXCLUDED.roles;

-- name: UpsertAuthorizationPolicy :exec
INSERT INTO authorization_policies(
	owner_client_id,
	consumer_client_id,
	roles)
VALUES (
	@owner_client_id,
	@consumer_client_id,
	@roles::TEXT[])
ON CONFLICT (
	owner_client_id,
	consumer_client_id)
	DO UPDATE SET
		roles = EXCLUDED.roles
	WHERE
		authorization_policies.roles IS DISTINCT FROM EXCLUDED.roles;

