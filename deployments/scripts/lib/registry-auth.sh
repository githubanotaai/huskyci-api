# shellcheck shell=bash
# Source from push scripts, e.g.:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=registry-auth.sh
#   . "${SCRIPT_DIR}/lib/registry-auth.sh"

# Normalizes and validates HUSKYCI_PUSH_TARGET: "ecr" or "docker" (default: docker).
huskyci_require_push_target() {
	HUSKYCI_PUSH_TARGET="${HUSKYCI_PUSH_TARGET:-docker}"
	case "${HUSKYCI_PUSH_TARGET}" in
	ecr | ECR) HUSKYCI_PUSH_TARGET=ecr ;;
	docker | dockerhub | hub | Docker) HUSKYCI_PUSH_TARGET=docker ;;
	*)
		echo "ERROR: HUSKYCI_PUSH_TARGET must be 'ecr' or 'docker', got: ${HUSKYCI_PUSH_TARGET}" >&2
		return 1
		;;
	esac
	export HUSKYCI_PUSH_TARGET
}

# Login to ECR. Requires ECR_REGISTRY and AWS_REGION. AWS CLI uses AWS_PROFILE if set.
huskyci_auth_ecr() {
	if [ -z "${ECR_REGISTRY:-}" ]; then
		echo "ERROR: Set ECR_REGISTRY to your registry host, e.g. <account_id>.dkr.ecr.<region>.amazonaws.com" >&2
		return 1
	fi
	if [ -z "${AWS_REGION:-}" ]; then
		echo "ERROR: Set AWS_REGION for ECR (e.g. us-east-1)" >&2
		return 1
	fi
	echo "▶ Authenticating to ECR at ${ECR_REGISTRY} (region ${AWS_REGION})"
	aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}"
}

# Optional Docker Hub login if DOCKERHUB_USER and DOCKERHUB_PASSWORD are set.
huskyci_auth_docker() {
	if [ -n "${DOCKERHUB_USER:-}" ] && [ -n "${DOCKERHUB_PASSWORD:-}" ]; then
		echo "▶ Authenticating to Docker Hub as ${DOCKERHUB_USER}"
		docker login -u "${DOCKERHUB_USER}" --password-stdin <<<"${DOCKERHUB_PASSWORD}"
	else
		echo "▶ Docker push: set DOCKERHUB_USER and DOCKERHUB_PASSWORD to log in, or rely on an existing host login"
	fi
}

# Call after huskyci_require_push_target.
huskyci_auth_for_push_target() {
	if [ "${HUSKYCI_PUSH_TARGET}" = "ecr" ]; then
		huskyci_auth_ecr
	else
		huskyci_auth_docker
	fi
}
