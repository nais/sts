ARG GO_VERSION=1.27.1

FROM golang:${GO_VERSION} AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . /workspace
RUN CGO_ENABLED=0 go test -c -tags=integration_test -o /sts-benchmark ./internal/integration

# The Job needs a shell to read its projected token before it starts the benchmark.
FROM alpine:3.23
COPY --from=builder /sts-benchmark /usr/local/bin/sts-benchmark
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sts-benchmark"]
