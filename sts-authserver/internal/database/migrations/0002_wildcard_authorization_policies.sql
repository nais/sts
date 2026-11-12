-- +goose Up
-- +goose StatementBegin
ALTER TABLE clients
	ADD COLUMN allow_all_consumers BOOLEAN DEFAULT FALSE NOT NULL,
	ADD COLUMN consumer_namespaces TEXT[] DEFAULT '{}' NOT NULL;

-- +goose StatementEnd
