#!/bin/bash
#
# Build and push the huskyci Gitleaks image to Docker Hub or Amazon ECR.
#
# Usage:
#   HUSKYCI_PUSH_TARGET=docker ./deployments/scripts/push-huskyci-gitleaks.sh
#   HUSKYCI_PUSH_TARGET=ecr ECR_REGISTRY=... AWS_REGION=us-east-1 ./deployments/scripts/push-huskyci-gitleaks.sh
#
# Environment:
#   HUSKYCI_PUSH_TARGET   ecr | docker   (default: docker)
#   ECR_REGISTRY          required for ecr — full host, no default account id in repo
#   AWS_REGION            required for ecr
#   GITLEAKS_ECR_REPOSITORY  ECR repo name (default: huskyci-gitleaks)
#   DOCKERHUB_ORG         namespace for docker target (default: huskyci)
#   DOCKERHUB_USER / DOCKERHUB_PASSWORD  optional login for Docker Hub
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-auth.sh
. "${SCRIPT_DIR}/lib/registry-auth.sh"

cd "${SCRIPT_DIR}/../.."

DOCKERFILE="deployments/dockerfiles/gitleaks/Dockerfile"
LOCAL_IMAGE="${GITLEAKS_LOCAL_IMAGE:-huskyci/gitleaks:build-temp}"
BUILDER_NAME="${HUSKYCI_BUILDX:-huskyci-buildx}"

huskyci_require_push_target

if [ "${HUSKYCI_PUSH_TARGET}" = "ecr" ]; then
	REMOTE_BASE="${ECR_REGISTRY}/${GITLEAKS_ECR_REPOSITORY:-huskyci-gitleaks}"
else
	REMOTE_BASE="${DOCKERHUB_ORG:-huskyci}/gitleaks"
fi

if ! docker buildx inspect "${BUILDER_NAME}" > /dev/null 2>&1; then
	echo "▶ Creating buildx builder '${BUILDER_NAME}'"
	docker buildx create --name "${BUILDER_NAME}" --use
else
	docker buildx use "${BUILDER_NAME}"
fi

echo "▶ Building ${LOCAL_IMAGE} (linux/amd64)"
docker buildx build \
	--platform linux/amd64 \
	--load \
	--file "${DOCKERFILE}" \
	--tag "${LOCAL_IMAGE}" \
	.

# Match push-containers.sh: version from running binary
gitleaksVersion=$(docker run --rm "${LOCAL_IMAGE}" gitleaks version | head -1 | tr -d '\r\n' | sed 's/^v//')
if [ -z "${gitleaksVersion}" ]; then
	echo "ERROR: could not read gitleaks version from image" >&2
	exit 1
fi

echo "▶ Gitleaks version tag: ${gitleaksVersion}"

echo "▶ Tagging local copies"
docker tag "${LOCAL_IMAGE}" "huskyci/gitleaks:${gitleaksVersion}"
docker tag "${LOCAL_IMAGE}" "huskyci/gitleaks:latest"

echo "▶ Auth and push to ${HUSKYCI_PUSH_TARGET} → ${REMOTE_BASE}"
huskyci_auth_for_push_target

docker tag "${LOCAL_IMAGE}" "${REMOTE_BASE}:${gitleaksVersion}"
docker tag "${LOCAL_IMAGE}" "${REMOTE_BASE}:latest"

docker push "${REMOTE_BASE}:${gitleaksVersion}"
docker push "${REMOTE_BASE}:latest"

echo "✅ Pushed ${REMOTE_BASE}:${gitleaksVersion} and :latest"
