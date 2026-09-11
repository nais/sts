-- name: GetSigningKeySet :one
SELECT *
FROM rotatable_signing_keys;

-- name: SaveSigningKeySet :exec
INSERT INTO rotatable_signing_keys (id, current_key, previous_key, next_key, expires_at)
VALUES (@id, @current_key, @previous_key, @next_key, @expires_at)
ON CONFLICT (id) DO UPDATE
SET current_key = EXCLUDED.current_key,
    previous_key = EXCLUDED.previous_key,
    next_key = EXCLUDED.next_key,
    expires_at = EXCLUDED.expires_at,
    updated_at = NOW();
