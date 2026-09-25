---
status: accepted
date: 2026-09-04
---

# Cache client registrations in snapshots

## Background

Token requests far outnumber registration changes. Reading clients and policies
from PostgreSQL for every request adds database work to the token path.

## Decision

Each STS pod keeps a complete snapshot of clients and authorization policies in
memory. Token requests read this snapshot instead of querying PostgreSQL for
every request.

Each pod reloads the snapshot:

- when PostgreSQL reports a change;
- when the database listener reconnects;
- every minute, in case a notification was missed;
- when PostgreSQL finds an entry missing from the snapshot.

If an entry is absent from the snapshot, STS queries PostgreSQL. If the entry
exists in PostgreSQL, STS returns it and requests a snapshot reload.

## Considered options

- Query PostgreSQL for every token request. This avoids stale data but adds a
  database query to each client and policy lookup.
- Use an external cache. This adds another service to operate.
- Cache individual entries. This requires per-entry invalidation or eviction.
- Keep a complete snapshot in each pod. This keeps the read path simple while
  registrations fit in memory.

## Consequences

Database triggers report writes from any client, so writers do not need
cache-specific code. STS loads clients and policies in one database transaction.
A failed reload leaves the previous snapshot available.

## Limitations

- Changes are not visible in every pod immediately. A cache miss can find a new
  entry, but an existing changed or deleted entry remains stale until the next
  reload.
- Every pod stores all clients and policies. Notifications can be coalesced,
  but refreshes still reload the full dataset. This works while registrations
  fit in memory and writes remain infrequent.

## Outcome

Local benchmarks on an Apple M4 Pro in September 2026 measured:

| Token flow         |      Before | With snapshot |
|--------------------|------------:|--------------:|
| Client credentials | ~1.81 ms/op |   ~0.88 ms/op |
| Token exchange     | ~2.75 ms/op |   ~0.94 ms/op |

These results do not estimate production capacity.
