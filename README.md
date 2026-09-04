# sts

Nais Security Token Service (STS) is an OAuth 2.1 authorization server for
workloads running on Nais.

STS issues short-lived security tokens for exactly one audience. Callers must be:

- authenticated with workload identity assertions and
- be granted access through audience's access rules

The service will support:

- [RFC 6749 Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) for machine-to-machine access
- [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) for on-behalf-of flows

## Development

Use [mise](https://mise.jdx.dev/):

```shell
mise tasks
```

Start the service locally:

```shell
mise run local
```

Server runs two listeners for public and internal use:

- `http://localhost:8080/.well-known/oauth-authorization-server`
- `http://localhost:8081/healthz`
- `http://localhost:8081/readyz`
- `http://localhost:8081/metrics`

Edit `.env` to override the local configuration.

## Performance

Run the end-to-end STS token endpoint benchmarks with:

```shell
mise run test:benchmark
```

Generate a standalone HTML report with endpoint timings, allocations, database
query timings, and token-processing step timings:

```shell
mise run test:benchmark-report
open benchmark-report/index.html
```

The report task runs each grant type separately so its captured OpenTelemetry
metrics can be attributed to the corresponding endpoint benchmark. Raw Go
output and Prometheus snapshots are kept in `benchmark-report/` alongside the
HTML report. Set `STS_BENCHMARK_REPORT_DIR` to use another output directory.

The benchmark starts PostgreSQL and the mock issuer to create fixture JWTs, then
measures only steady-state HTTP requests to the STS `/token` endpoint. Fixture
creation and one cache-warming STS request are outside the timer. Client
credentials and token exchange are reported separately.

Metrics use the OpenTelemetry API and are exported in Prometheus format on the
internal `/metrics` endpoint. They include:

- standard `http_server_*` request duration, active request, and body-size
  metrics from `otelchi`;
- `sts_token_step_duration_seconds`, labeled by outcome and issuance step:
  client assertion verification, client lookup, subject-token verification,
  target authorization, signing-key retrieval, and token signing;
- `sts_database_queries_total` and the standard
  `db_client_operation_duration_seconds`, labeled by SQL operation, outcome,
  and low-cardinality sqlc query name (for example `GetKubernetesClient` or
  `GetAuthorizationPolicy`);
- standard `db_client_connection_count`, `db_client_connection_max`, and
  `db_client_connection_wait_time_seconds` pool metrics, plus acquisition counts.

These metrics separate database, connection-pool, verification/key retrieval,
and signing costs when deciding where optimization or caching is useful.
