# Benchmarks

## Run the benchmarks

Run the Go benchmarks:

```shell
mise run test:benchmark
```

Generate an HTML report with token request timings, allocations, database queries, and token-processing steps:

```shell
mise run test:benchmark-report
open benchmark-report/index.html
```

The report task runs each grant separately.
It writes raw Go output, Prometheus snapshots, and the HTML report to `benchmark-report/`.

Set `STS_BENCHMARK_REPORT_DIR` to use another directory.

## Measurements

The benchmark starts PostgreSQL and a mock issuer, then creates fixture tokens.
It sends one request to warm the JWKS and signing-key caches before timing requests to `/token`.

Go reports time, bytes, and allocations for the timed requests.
Setup and the warm-up request are outside the timer.

Timed requests include JWT verification, client and policy lookups, and token signing.

## Report metrics

The report collects Prometheus metrics after each grant benchmark.
Unlike the Go timings, the counters and histograms also include STS setup and warm-up.

Pool gauges show values at snapshot time.

The metrics include:

- HTTP request duration, active requests, and body size;
- token grant and issuance step durations;
- PostgreSQL query counts and durations;
- connection acquisition counts, wait times, and pool connection counts.

The HTML report shows database query and token step timings, but not grant-duration histograms.
Its p95 values use histogram bucket bounds.
Treat the metrics as process-level context, not timed-iteration measurements.

## Local observability and traffic

With `mise run local` active, start [Grafana](http://localhost:3000/d/sts-local-performance) and [Prometheus](http://localhost:9090):

```shell
mise run local:observability
```

Normal local startup does not start them.

Generate fixture-based token requests until Ctrl-C:

```shell
mise run local:traffic
```

The default is 100 requests per second with eight workers.
Adjust the rate, workers, duration, or flow:

```shell
mise run local:traffic --rate 500 --workers 16 --duration 5m
mise run local:traffic --rate 0 --workers 8 --flow token_exchange
```

This tool generates local traffic.
It does not replace the benchmarks or a production load test.
