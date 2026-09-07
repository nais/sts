-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION notify_sts_cache_changed()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- The transaction ID lets listeners correlate writes while PostgreSQL folds
    -- duplicate notifications from the same transaction into one event.
    PERFORM pg_notify('sts_cache_changed', txid_current()::TEXT);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER kubernetes_clients_cache_changed
AFTER INSERT OR UPDATE OR DELETE ON kubernetes_clients
FOR EACH STATEMENT
EXECUTE FUNCTION notify_sts_cache_changed();

CREATE TRIGGER authorization_policies_cache_changed
AFTER INSERT OR UPDATE OR DELETE ON authorization_policies
FOR EACH STATEMENT
EXECUTE FUNCTION notify_sts_cache_changed();

-- +goose Down
DROP TRIGGER authorization_policies_cache_changed ON authorization_policies;
DROP TRIGGER kubernetes_clients_cache_changed ON kubernetes_clients;
DROP FUNCTION notify_sts_cache_changed();
