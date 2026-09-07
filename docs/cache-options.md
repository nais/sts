# Snapshot cache for STS

_Date: 2026-09-04_

## Chosen approach

STS uses a complete, immutable in-memory snapshot of clients and authorization
policies in every pod.

The snapshot refreshes:

- immediately after PostgreSQL `LISTEN` receives a write notification;
- every minute as a fallback;
- after the listener reconnects.

No external cache or per-entry eviction is needed.

## Generic cache

`internal/cache.Snapshot[T]` stores any immutable value `T` and accepts a loader:

```go
snapshot, err := cache.NewSnapshot(
    func(ctx context.Context) (*State, error) {
        return loadCompleteState(ctx)
    },
    time.Minute,
)
```

Its small API is:

```go
snapshot.Initialize(ctx) // blocking initial load
snapshot.Current()       // read under a short RWMutex read lock
snapshot.Trigger()       // coalesced, non-blocking refresh request
snapshot.Run(ctx, onError)
```

A load creates a new value and replaces it under a short `sync.RWMutex` write
lock. Readers see either the old complete snapshot or the new complete snapshot,
never a partially updated one.
If a refresh fails, the old snapshot remains available.

`Trigger` uses a buffered signal of size one. Many writes close together are
coalesced because one full refresh observes all committed data.

## PostgreSQL notifications

Migration `0002_cache_notifications.sql` adds statement-level triggers to:

- `kubernetes_clients`;
- `authorization_policies`.

Every insert, update, or delete runs:

```sql
SELECT pg_notify('sts_cache_changed', txid_current()::TEXT);
```

The transaction ID is the event ID. PostgreSQL sends the notification only after
the transaction commits. Multiple matching notifications in one transaction may
be folded into one, which is fine because the cache reloads all data.

`internal/cache.PostgresListener` owns one dedicated pooled connection per pod.
It subscribes before the initial snapshot is loaded, avoiding a gap between the
load and `LISTEN`. It reconnects with backoff and triggers a refresh after every
reconnect.

## STS snapshot

`internal/store.CachedClient` loads both tables in one read-only,
repeatable-read transaction:

```text
ListKubernetesClients
ListAuthorizationPolicies
```

It builds two maps:

```text
client: issuer + namespace + workload
policy: owner_client_id + consumer_client_id
```

The public token path reads these maps first. On a miss, it performs the original
point query against PostgreSQL and returns that result immediately. A successful
fallback also triggers a complete refresh so later requests can use the snapshot.
Missing database rows still fail as `invalid_client`.

API writes will still use PostgreSQL; database triggers notify every pod without
requiring each API handler to remember cache-specific logic.

## Lifecycle

At startup STS:

1. creates the cached client store;
2. executes `LISTEN`;
3. performs the initial blocking snapshot load;
4. starts the HTTP servers and cache worker.

At runtime:

1. a database write commits;
2. every listening pod receives its transaction ID;
3. each pod requests a snapshot refresh;
4. close-together requests are coalesced;
5. the completed snapshot replaces the old snapshot under the write lock.

The one-minute timer handles a missed notification. A listener reconnect also
refreshes immediately.

## Trade-offs

### Positives

- Simple read path and concurrency model.
- No Redis, Otter, event log, or per-key eviction.
- Inserts, updates, deletes, and cascades appear together.
- Triggers cover writes from future APIs and other database clients.
- Failed refreshes do not destroy the last valid state.
- A newly inserted entry works immediately through PostgreSQL fallback, even if
  its notification has not been processed yet.
- One notification can represent a transaction containing many writes.

### Limitations

- Every pod holds the complete dataset in memory.
- Every write reloads both complete tables in every pod.
- Unknown clients and policies perform a PostgreSQL point query, so repeated
  invalid requests are not fully isolated from the database.
- Fallback fixes new-entry misses, but cannot detect a stale existing entry or a
  deletion still present in the old snapshot.
- During a listener failure, stale data may remain until reconnect or the
  one-minute periodic refresh.
- This is eventually consistent after commit, not strictly consistent.
- One PostgreSQL pool connection per pod is reserved for `LISTEN`.

This is appropriate while clients/policies fit comfortably in memory and writes
are much less frequent than token requests. If reload cost later becomes
significant, notification payloads can identify a table/key and the same generic
cache can be replaced or extended without changing the authorization interface.

## Initial benchmark result

On the local Apple M4 Pro benchmark after enabling the snapshot:

| Flow | Before | Snapshot | Change |
|---|---:|---:|---:|
| Client credentials | ~1.81 ms/op | ~0.88 ms/op | ~51% faster |
| Token exchange | ~2.75 ms/op | ~0.94 ms/op | ~66% faster |

These are local results and should not be treated as production capacity, but
they confirm that removing per-request PostgreSQL reads materially changes the
hot path.

## Sources

- PostgreSQL `NOTIFY`: <https://www.postgresql.org/docs/18/sql-notify.html>
- PostgreSQL `LISTEN`: <https://www.postgresql.org/docs/18/sql-listen.html>
- Local benchmark: [`benchmark-report/index.html`](../benchmark-report/index.html)
