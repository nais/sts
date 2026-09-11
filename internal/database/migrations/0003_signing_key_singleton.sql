-- +goose Up
-- The application manages one current/previous/next key set. A unique index on
-- a constant enforces that invariant without changing the existing row ID.
CREATE UNIQUE INDEX rotatable_signing_keys_singleton
ON rotatable_signing_keys ((TRUE));

-- +goose Down
DROP INDEX rotatable_signing_keys_singleton;
