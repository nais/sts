FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder
ENV CGO_ENABLED=0
WORKDIR /src

# Build from the repository root to include the locally replaced authserver API.
COPY sts-operator/go.mod sts-operator/go.sum ./
COPY sts-operator/api/go.mod sts-operator/api/go.sum ./api/
COPY sts-authserver/api/go.mod sts-authserver/api/go.sum /sts-authserver/api/
RUN go mod download

COPY sts-operator/ .
COPY sts-authserver/api/ /sts-authserver/api/
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o bin/sts-operator ./cmd/sts-operator

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /src/bin/sts-operator /app/sts-operator
ENTRYPOINT ["/app/sts-operator"]
