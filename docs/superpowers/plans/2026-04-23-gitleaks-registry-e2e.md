# Gitleaks and registry changes — E2E and CI contract tests (implementation plan)

> **For agentic workers:** use this as a checklist; steps match what landed in the repo.

**Goal:** Add CI contract tests for the Gitleaks v8 image, a controlled `gitleaks dir` finding, and bash syntax for deployment/push scripts—without duplicating [api/securitytest](api/securitytest) / [api/context](api/context) unit tests.

**Tech stack:** GitHub Actions, Docker, bash, `jq` (on `ubuntu-latest`).

---

## Checklist (implementation)

- [x] **Task 1:** Add CI job: build [deployments/dockerfiles/gitleaks/Dockerfile](deployments/dockerfiles/gitleaks/Dockerfile), assert `gitleaks version` is v8.x
- [x] **Task 2:** Add fixture dir with one known finding; CI runs `gitleaks dir` in image, assert `jq length == 1`
- [x] **Task 3:** Add [deployments/scripts/verify-depl-scripts.sh](deployments/scripts/verify-depl-scripts.sh) (`bash -n` on registry/push scripts); run in CI
- [x] **Task 4:** Document in [README](README.md): what CI covers + optional manual API/docker-compose e2e for `HUSKYCI_GITLEAKS_*`
- [x] **Task 5:** Save this file under `docs/superpowers/plans/`

**Already unit-tested (not duplicated here):** v8 JSON unmarshal, Sonar goldens, `HUSKYCI_GITLEAKS_IMAGE` / `HUSKYCI_GITLEAKS_IMAGE_TAG` in [api/context](api/context).

**Out of scope for CI:** real `docker push` to ECR or Docker Hub (no credentials in public runs).

---

## Commands reference (as implemented in `ci.yaml`)

- Build: `docker build -f deployments/dockerfiles/gitleaks/Dockerfile -t huskyci/gitleaks:ci .`
- Version: `docker run --rm huskyci/gitleaks:ci gitleaks version | grep -E 'v?8\.'`
- Fixture: mount `api/securitytest/testdata/gitleaks_e2e_fixture` to `/scan`, output JSON to stdout, `jq 'length'`

## Success criteria

- Gitleaks image builds in CI and v8 is asserted.
- One `gitleaks dir` run proves JSON output and rule matching on a fixture.
- `bash -n` passes for deployment shell entrypoints.
- README points operators to manual full-stack e2e if they need it.
