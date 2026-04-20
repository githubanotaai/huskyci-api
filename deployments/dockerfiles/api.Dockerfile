FROM golang:1.23-alpine AS builder

RUN apk update && apk upgrade \
    && apk add --no-cache git

WORKDIR /build

COPY api/go.mod api/go.sum ./
RUN go mod download

COPY api/ ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /huskyci-api-bin server.go

FROM alpine:3.21

RUN apk update && apk upgrade \
    && apk add --no-cache ca-certificates

WORKDIR /go/src/github.com/githubanotaai/huskyci-api/api/

COPY --from=builder /huskyci-api-bin .
COPY api/config.yaml .

RUN chmod +x huskyci-api-bin
