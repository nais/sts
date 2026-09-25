# sts

Nais Security Token Service (STS) is an OAuth 2.1 authorization server for
workloads running on Nais.

STS issues short-lived security tokens for exactly one audience. Callers must be:

- authenticated with workload identity assertions and
- be granted access through audience's access rules

The service will support:

- [RFC 6749 Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) for machine-to-machine access
- [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) for on-behalf-of flows

## Documentation

- [Client registration](docs/registration.md)

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

The local setup copies `config.example.yaml` to the gitignored `config.yaml`.
Edit `config.yaml` to change the local configuration.

Set `CONFIG_FILE` to use
another file. STS reads all application configuration from that YAML file and
rejects unknown fields.

### Database migrations

To squash applied migrations, run `mise run squash-migrations`. Before the first
deployment, pass `0001` to restart numbering. Reset the local database after
renumbering. Do not renumber migrations after deployment.

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

### Local observability and traffic

With STS running through `mise run local`, start the Prometheus and Grafana
services declared in `docker-compose.yaml`:

```shell
mise run local:observability
```

Open the provisioned STS dashboard at
[http://localhost:3000/d/sts-local-performance](http://localhost:3000/d/sts-local-performance).
Prometheus is available at [http://localhost:9090](http://localhost:9090).
Both services are behind the Compose `observability` profile and are not started
by the normal local setup.

Generate an even mix of client credentials and token exchange requests until
Ctrl-C:

```shell
mise run local:traffic
```

The default is 100 requests per second with eight workers, which should leave a
development machine responsive. The rate, concurrency, duration, and flow are
configurable:

```shell
mise run local:traffic --rate 500 --workers 16 --duration 5m
mise run local:traffic --rate 0 --workers 8 --flow token_exchange
```

A rate of `0` removes pacing; concurrency remains bounded by `--workers`. The
traffic generator refreshes its mock fixture tokens every 30 minutes and prints
request rate, errors, and latency every five seconds.
