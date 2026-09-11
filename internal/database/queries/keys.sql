-- name: GetActiveSigningKey :one
SELECT *
FROM signing_keys
WHERE activated_at IS NOT NULL
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY activated_at DESC
LIMIT 1;

-- name: ListValidSigningKeys :many
SELECT *
FROM signing_keys
WHERE expires_at IS NULL
   OR expires_at > NOW()
ORDER BY created_at DESC;

-- name: InsertSigningKey :exec
INSERT INTO signing_keys (kid, algorithm, private_key, activated_at)
VALUES (@kid, @algorithm, @private_key, @activated_at);

-- name: GetKeys :one
SELECT *
FROM rotatable_signing_keys
LIMIT 1;

-- name: InsertKey :exec
INSERT INTO rotatable_signing_keys (id, current_key, previous_key, next_key, expiry)
VALUES (@id, @current_key, @previous_key, @next_key, @expiry);
