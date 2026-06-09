# Dockerfile used to create "huskyci/enry" image
# https://github.com/go-enry/go-enry
FROM golang:alpine as builder

RUN apk update && apk upgrade \
	&& apk add --update --no-cache git

RUN git clone --depth 1 --branch v2.9.6 https://github.com/go-enry/go-enry.git && \
    cd go-enry && \
	CGO_ENABLED=0 go build -o /usr/bin/enry ./cmd/enry

FROM alpine:latest

RUN apk update && apk upgrade \
	&& apk add --update --no-cache git openssh-client

COPY --from=builder /usr/bin/enry /usr/bin
