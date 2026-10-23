# Benchmarks

## Run the benchmarks

Run the Go benchmarks:

```shell
mise -C sts-authserver run test:benchmark
```

Generate an HTML report with token request timings, allocations, database queries, and token-processing steps:

```shell
mise -C sts-authserver run test:benchmark-report
open sts-authserver/benchmark-report/index.html
```

The report task runs each grant separately.
It writes raw Go output, Prometheus snapshots, and the HTML report to `sts-authserver/benchmark-report/`.

Set `STS_BENCHMARK_REPORT_DIR` to use another directory.
Relative report directory paths resolve from `sts-authserver/`.

## Benchmark deployed STS

Keep the HPA minimum and maximum at two replicas for a stable run.
Wait for both replicas to be ready.
Select the Kubernetes context for the deployment before this command:

```shell
mise -C sts-authserver run test:benchmark-remote \
  --sts-url https://sts.dev.dev-nais.cloud.nais.io \
  --namespace nais-system \
  --deployment sts \
  --client-namespace basseng \
  --service-account workload1 \
  --target env1:basseng:workload2 \
  --benchtime 10s
open sts-authserver/benchmark-report/remote/index.html
```

Use an ingress URL for `--sts-url`.
The report labels this request path as ingress.
It creates one workload token for both the client assertion and subject token.
The workload issuer must be configured for both client authentication and subject tokens.
The client and target authorization policy must already exist.

The task starts a metrics port-forward for each STS pod and stops them on exit.
Your Kubernetes identity needs permission to read pods and Deployments, create service-account tokens, and port-forward pods.
Local ports start at 18081; use `--metrics-port` to change the first port.
No manual port-forward or local database is required.

The report sums before/after histogram differences from all replicas.
Server metrics include warm-up, benchmark calibration, and any concurrent traffic between snapshots.
If a metrics scrape fails or pods change or restart, the report omits server metrics and displays a warning.
Request timings remain available.

Remote timings include the network, ingress, and STS processing.
Remote allocations describe the benchmark client, not the STS server.
The default token lifetime request is one hour; keep the total run below the granted lifetime.
The task does not refresh tokens or change the HPA.

Remote output defaults to `sts-authserver/benchmark-report/remote/`.
Set `STS_BENCHMARK_REPORT_DIR` to use another directory.
The local benchmark and report tasks retain their existing behavior.

### Benchmark from inside the cluster

The cluster task runs the benchmark client as a Kubernetes Job and sends requests to the STS Service.
Publish the image on demand with the `authserver-benchmark-image` GitHub Actions workflow:

```shell
gh workflow run authserver-benchmark-image.yaml --ref main
```

Use `--ref` to select the source branch.
GitHub requires the workflow on the default branch before it accepts manual runs.
The workflow builds, signs, and publishes a Linux amd64 image to the existing Artifact Registry.
It does not run benchmarks or deploy STS.
Copy the benchmark command with the immutable image reference from the completed run summary.

Alternatively, build and push the image locally from the repository root:

```shell
docker build --platform linux/amd64 -f hack/benchmark.Dockerfile -t <registry>/sts-benchmark:<tag> sts-authserver
docker push <registry>/sts-benchmark:<tag>
```

The image architecture must match the cluster nodes that run the Job.
Run the task with the pushed image:

```shell
mise -C sts-authserver run test:benchmark-cluster --image <registry>/sts-benchmark:<tag>
```

The default STS URL is `http://sts.nais-system.svc`.
The task uses client namespace `basseng`, service account `workload1`, and target `env1:basseng:workload2`.
The service account, client registration, and target authorization policy must already exist.

The task shares remote server-metrics collection, which forwards each STS pod locally.
It runs one Job per grant and attempts to delete both Jobs on exit.
If deletion fails, the task prints a manual cleanup command.
Kubernetes also deletes finished Jobs after ten minutes.
Job logs and the HTML report go to `sts-authserver/benchmark-report/cluster/`.
Server metrics include concurrent traffic during Job startup as well as the benchmark requests.
Timed requests exclude Job startup.
The default Service URL bypasses ingress and the external client network.

To measure ingress from the same Job, override the URL:

```shell
STS_BENCHMARK_REPORT_DIR=benchmark-report/cluster-ingress \
  mise -C sts-authserver run test:benchmark-cluster --image <registry>/sts-benchmark:<tag> \
  --sts-url https://sts.dev.dev-nais.cloud.nais.io
```

`hack/sts-netpol.yaml` permits Job egress to the ingress address `10.0.2.200` on TCP 443.
Use the hostname rather than the IP address so TLS verification and ingress routing work.

The Job projects a service-account token with audience `nais` for both the assertion and subject token.
The benchmark reads the token file before the timed requests.
The runtime image contains only the benchmark binary and CA certificates.
Your Kubernetes identity needs permission to read, create, and delete Jobs, and read pod logs.
The STS pod and port-forward permissions from the remote task also apply.
If NetworkPolicies restrict traffic, permit the Job to resolve DNS and connect to STS on pod port 8080.
Permit that connection in both the Job egress rules and the STS ingress rules.
The Job pods have the label `app=sts-benchmark`.

The benchmark task does not publish images or change NetworkPolicies.

## Measurements

The local benchmark starts PostgreSQL and a mock issuer, then creates fixture tokens.
Every mode sends one request to warm the JWKS and signing-key caches before timed requests to `/token`.

Go reports time, bytes, and allocations for the timed requests.
Setup and the warm-up request are outside the timer.

Timed requests include JWT verification, client and policy lookups, and token signing.

## Report metrics

The local report collects Prometheus metrics after each grant benchmark.
Unlike the Go timings, these counters and histograms also include STS setup and warm-up.

Remote and cluster reports use before/after snapshots from each STS pod.
Their histogram deltas include warm-up, calibration, and concurrent traffic, but exclude earlier STS setup.

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

With `mise run sts-authserver:mock` active, start [Grafana](http://localhost:3000/d/sts-local-performance) and [Prometheus](http://localhost:9090):

```shell
mise -C sts-authserver run dev:observability
```

Normal local startup does not start them.

Generate fixture-based token requests until Ctrl-C:

```shell
mise -C sts-authserver run mock:traffic
```

The default is 100 requests per second with eight workers.
Adjust the rate, workers, duration, or flow:

```shell
mise -C sts-authserver run mock:traffic --rate 500 --workers 16 --duration 5m
mise -C sts-authserver run mock:traffic --rate 0 --workers 8 --flow token_exchange
```

This tool generates local traffic.
It does not replace the benchmarks or a production load test.
