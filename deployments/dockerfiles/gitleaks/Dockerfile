# Dockerfile used to create "huskyci/gitleaks" image
# https://github.com/gitleaks/gitleaks/pkgs/container/gitleaks
# https://hub.docker.com/r/huskyci/gitleaks/

ARG GITLEAKS_VERSION=8.30.1
FROM ghcr.io/gitleaks/gitleaks:v${GITLEAKS_VERSION}

RUN apk add --no-cache ca-certificates openssh-client jq

ENTRYPOINT []
CMD ["/bin/sh"]
