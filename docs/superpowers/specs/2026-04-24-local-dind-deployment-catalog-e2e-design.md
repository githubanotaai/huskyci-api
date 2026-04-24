# Local HuskyCI e2e via Docker-in-Docker — `deployment-catalog` (design)

**Status:** Approved direction (Approach 1).  
**Date:** 2026-04-24.  
**Update:** Gitleaks-only success scope; Wiz deferred.

## Goal

Exercise the current HuskyCI stack **locally** using the existing **Docker-in-Docker** layout (`deployments/docker-compose.yml`: `dockerapi` + API + Mongo), with analysis driven by **`huskyci-client`** against a **remote Git URL** and branch for `deployment-catalog` (same tree as a `git clone`, not uncommitted local-only disk state).

## Success criteria (narrow)

The run is considered **successful** when **Gitleaks** (generic security test `gitleaks`) completes without clone or runner faults: no `ERROR_CLONING`, `ERROR_TIMEOUT_GITLEAKS`, or `ERROR_RUNNING_GITLEAKS`; output is valid for the existing analyzer (JSON path as in `api/config.yaml`).

**Wiz CLI (`wizcli`)** is **not** in scope: the integration is incomplete (Mongo upsert wiring, ECR image, tenant credentials). Do not require Wiz to pass for this e2e.

### Isolating Gitleaks from other generics

`runGenericScans` fails the whole analysis if **any** default generic test’s `Start()` returns an error. So for a **Gitleaks-only** local run, **`wizcli` must not run as a default generic test**—otherwise a Wiz auth or image pull failure can fail the analysis even when Gitleaks would have succeeded.

Practical options:

- Rely on a **fresh Mongo** volume where `wizcli` was never upserted (today’s codebase often omits `wizcli` from `checkEachSecurityTest`, so Wiz may not appear in `securityTest` at all).
- Or set **`default: false`** on the `wizcli` document in Mongo for your dev database.
- Do not add `wizcli` to the startup upsert path until Wiz is product-ready.

Other work may still run in parallel (**gitauthors**, **enry**, language-specific tools). They are **not** part of this success definition unless they block the analysis.

## Architecture (unchanged from stock compose)

- **`dockerapi`**: `docker:24-rc-dind`, privileged, Docker API on TCP `2376`, TLS assets under `deployments/certs`.
- **`api`**: `HUSKYCI_INFRASTRUCTURE_USE=docker`, connects to DinD, upserts security tests into Mongo at startup, orchestrates scanner containers **on the DinD daemon** (no bind-mount of `~/Gits/deployment-catalog` from the Mac).
- **`huskyci-client`**: `POST /analysis` with `HUSKYCI_CLIENT_REPO_URL`, `HUSKYCI_CLIENT_REPO_BRANCH`, `HUSKYCI_CLIENT_API_ADDR`, and a **Husky-Token** minted for the **same** repository URL as used in the analysis request.

## Prerequisites

### Repository

- A **cloneable** HTTPS or SSH URL and branch for `deployment-catalog` (must match the URL used when minting the Husky token).
- For private remotes: configure **`GIT_PRIVATE_SSH_KEY`** (or documented substitute) so scanner images can clone, consistent with existing HuskyCI docs.

### Gitleaks

- DinD must reach the registry for **`huskyci/gitleaks`** (or set **`HUSKYCI_GITLEAKS_IMAGE`** / **`HUSKYCI_GITLEAKS_IMAGE_TAG`** on the API service to an image DinD can pull).

### Wiz (deferred)

No Wiz-specific env, ECR login, or policy setup is required for this e2e. When Wiz is implemented end-to-end, a follow-up design can extend success criteria and prerequisites.

## Procedure summary (Approach 1)

1. Start **`deployments/docker-compose.yml`** from the `deployments/` directory; wait for Mongo health and API listening on **8888**.
2. Confirm **`GET /healthcheck`** and review API logs for requirement checks.
3. Mint a Husky token: **`POST /api/1.0/token`** with API basic auth; JSON body must include the **same `repositoryURL`** you will analyze.
4. Run **`huskyci-client`** with the client env vars pointing at `http://127.0.0.1:8888` (or the published host port) and the remote URL/branch for `deployment-catalog`.
5. Validate success via client output and/or **`GET /analysis/:RID`** JSON: inspect the **`gitleaks`** container (`CResult`, absence of error markers in captured output as above).

## Risks

- **First-run latency:** Many images pulled into DinD; clone depth and repo size affect wall time.
- **Apple Silicon:** Scanner images may require **`linux/amd64`**; document platform flags if pulls fail.
- **Language scans:** A failing language tool can still fail the overall analysis (`runLanguageScans`); if the repo triggers heavy or flaky scanners, consider a minimal fixture repo or `HUSKYCI_LANGUAGE_EXCLUSIONS` for local runs (implementation plan detail).

## Out of scope

- **Wiz CLI** e2e until fully wired and stable.
- Host bind-mount of `~/Gits/deployment-catalog` into scanners (not supported by current `CreateContainer` host config).
- Replacing DinD with host Docker for the API’s `docker` infrastructure mode (different test).

## Next step

After review of this document, produce an **implementation plan** (`writing-plans` skill): exact compose commands, token `curl` example, client env block, and checks that **`wizcli` is not a failing default generic** for Gitleaks-only validation.
