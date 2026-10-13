FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . /workspace

RUN CGO_ENABLED=0 go build -o sts ./cmd/sts

FROM cgr.dev/chainguard/static:latest@sha256:fe55470f22d3259488d9d3739168d8f04da67755f0b69382bc26eda4a7d3d327
WORKDIR /

COPY --from=builder /workspace/sts /usr/local/bin/sts

ENTRYPOINT ["/usr/local/bin/sts"]
