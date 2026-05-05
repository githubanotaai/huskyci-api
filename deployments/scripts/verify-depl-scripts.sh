#!/usr/bin/env bash
# Syntax-check deployment shell entrypoints. Safe for CI (no ECR, no push).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${ROOT}/lib/registry-auth.sh"
GITLEAKS="${ROOT}/push-huskyci-gitleaks.sh"
CLIENT_ECR="${ROOT}/push-huskyci-client-ecr.sh"
for f in "$LIB" "$GITLEAKS" "$CLIENT_ECR"; do
  bash -n "$f" || exit 1
  echo "ok: bash -n $f"
done
echo "verify-depl-scripts: all checks passed"
