FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download

COPY . /workspace

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o sts ./cmd/sts

FROM cgr.dev/chainguard/static:latest@sha256:fe55470f22d3259488d9d3739168d8f04da67755f0b69382bc26eda4a7d3d327
WORKDIR /

COPY --from=builder /workspace/sts /usr/local/bin/sts

ENTRYPOINT ["/usr/local/bin/sts"]
