FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY client/ ./client/
WORKDIR /app/client
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /huskyci-client ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git openssh-client
COPY --from=builder /huskyci-client /usr/local/bin/huskyci-client
ENTRYPOINT ["huskyci-client"]
