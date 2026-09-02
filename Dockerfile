ARG GO_VERSION=1.27.1

FROM golang:${GO_VERSION} AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . /workspace

RUN CGO_ENABLED=0 go build -o sts ./cmd/sts

FROM cgr.dev/chainguard/static:latest
WORKDIR /

COPY --from=builder /workspace/sts /usr/local/bin/sts

ENTRYPOINT ["/usr/local/bin/sts"]
