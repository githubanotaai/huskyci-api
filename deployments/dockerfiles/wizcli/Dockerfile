# Dockerfile used to create "huskyci/wizcli" image
# ECR: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      git \
      openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Download wizcli v1 binary (AMD64)
# For Gov/FIPS: https://downloads.wiz.us/v1/wizcli/latest/wizcli-fips-linux-amd64
RUN curl -sSLo /usr/local/bin/wizcli \
      https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-amd64 \
    && chmod +x /usr/local/bin/wizcli

WORKDIR /code

ENTRYPOINT []
CMD ["/bin/sh"]
