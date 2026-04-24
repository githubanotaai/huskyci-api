#!/bin/bash
#
# Build and push the huskyci-client image to ECR.
#
# Usage:
#   ./deployments/scripts/push-huskyci-client-ecr.sh [IMAGE_TAG]
#
# Environment variables (all have defaults):
#   AWS_REGION    - AWS region where the ECR repository lives  (default: us-east-1)
#   ECR_REGISTRY  - ECR registry host (required — no default account id in the repo)
#   IMAGE_NAME    - ECR repository name                        (default: huskyci-client)
#   IMAGE_TAG     - Tag to apply to the image                  (default: latest, or first positional arg)
#
# Requirements:
#   - AWS CLI configured with credentials that have ECR push permissions
#   - Docker with buildx support (Docker 19.03+)
#
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
IMAGE_NAME="${IMAGE_NAME:-huskyci-client}"
IMAGE_TAG="${1:-${IMAGE_TAG:-latest}}"

if [ -z "${ECR_REGISTRY:-}" ]; then
  echo "ERROR: ECR_REGISTRY is not set. Example: export ECR_REGISTRY=<account_id>.dkr.ecr.<region>.amazonaws.com" >&2
  exit 1
fi

FULL_IMAGE="${ECR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
DOCKERFILE="deployments/dockerfiles/huskyci-client.Dockerfile"
BUILDER_NAME="huskyci-buildx"

echo "▶ Image  : ${FULL_IMAGE}"
echo "▶ Region : ${AWS_REGION}"

# Ensure we run from the repo root regardless of where the script is called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

# Create/reuse a dedicated buildx builder that supports linux/amd64
if ! docker buildx inspect "${BUILDER_NAME}" > /dev/null 2>&1; then
  echo "▶ Creating buildx builder '${BUILDER_NAME}'"
  docker buildx create --name "${BUILDER_NAME}" --use
else
  docker buildx use "${BUILDER_NAME}"
fi

echo "▶ Authenticating with ECR"
aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${ECR_REGISTRY}"

echo "▶ Building and pushing ${FULL_IMAGE} (linux/amd64)"
docker buildx build \
  --platform linux/amd64 \
  --file "${DOCKERFILE}" \
  --tag "${FULL_IMAGE}" \
  --push \
  .

echo "▶ Verifying image in ECR"
aws ecr describe-images \
  --repository-name "${IMAGE_NAME}" \
  --region "${AWS_REGION}" \
  --image-ids imageTag="${IMAGE_TAG}" \
  --query 'imageDetails[0].{digest:imageDigest,pushed:imagePushedAt,size:imageSizeInBytes}' \
  --output table

echo "✅ Done: ${FULL_IMAGE}"
