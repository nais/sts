-- +goose Up
-- +goose StatementBegin
ALTER TABLE clients
	ADD COLUMN allow_all BOOLEAN DEFAULT FALSE NOT NULL,
	ADD COLUMN allowed_namespaces TEXT[] DEFAULT '{}' NOT NULL;

-- +goose StatementEnd
