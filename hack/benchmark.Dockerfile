ARG GO_VERSION=1.27

FROM golang:${GO_VERSION} AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download
COPY . /workspace
RUN CGO_ENABLED=0 go test -c -tags=integration_test -o /sts-benchmark ./internal/integration

FROM scratch
COPY --from=builder /sts-benchmark /usr/local/bin/sts-benchmark
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sts-benchmark"]
