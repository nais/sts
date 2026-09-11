-- +goose Up
CREATE TABLE kubernetes_clients
(
    id             TEXT        NOT NULL PRIMARY KEY,
    environment    TEXT        NOT NULL,
    namespace      TEXT        NOT NULL,
    workload       TEXT        NOT NULL,
    issuer         TEXT        NOT NULL,
    allowed_scopes TEXT[]      NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workload, namespace, issuer)
);

-- Which client may request tokens for which target client, and with which roles.
CREATE TABLE authorization_policies
(
    owner_client_id    TEXT NOT NULL REFERENCES kubernetes_clients (id) ON DELETE CASCADE,
    consumer_client_id TEXT NOT NULL,
    roles              TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (owner_client_id, consumer_client_id)
);

-- Keys are stored as raw JWK
CREATE TABLE rotatable_signing_keys
(
    id           UUID        NOT NULL PRIMARY KEY,
    current_key  BYTEA       NOT NULL,
    previous_key BYTEA       NOT NULL,
    next_key     BYTEA       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
