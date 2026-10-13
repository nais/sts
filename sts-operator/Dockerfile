FROM --platform=$BUILDPLATFORM golang:1.27.1 AS builder
ENV CGO_ENABLED=0
WORKDIR /src

COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o bin/sts-operator ./cmd/sts-operator

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /src/bin/sts-operator /app/sts-operator
ENTRYPOINT ["/app/sts-operator"]
