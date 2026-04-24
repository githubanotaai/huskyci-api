FROM golang:1.23-alpine AS builder

RUN apk update && apk upgrade \
    && apk add --no-cache git

WORKDIR /build

COPY client/go.mod client/go.sum ./
RUN go mod download

COPY client/ ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /huskyci-client ./cmd/main.go

FROM alpine:3.21

RUN apk update && apk upgrade \
    && apk add --no-cache \
    ca-certificates \
    curl \
    git \
    openssh-client

COPY --from=builder /huskyci-client /usr/local/bin/huskyci-client

COPY deployments/dockerfiles/huskyci-client/huskyci-client-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
CMD ["huskyci-client"]
