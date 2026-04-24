# Local HuskyCI e2e via Docker-in-Docker — `deployment-catalog` (design)

**Status:** Approved direction (Approach 1).  
**Date:** 2026-04-24.

## Goal

Exercise the current HuskyCI stack **locally** using the existing **Docker-in-Docker** layout (`deployments/docker-compose.yml`: `dockerapi` + API + Mongo), with analysis driven by **`huskyci-client`** against a **remote Git URL** and branch for `deployment-catalog` (same tree as a `git clone`, not uncommitted local-only disk state).

## Success criteria (narrow)

The run is considered **successful** when:

1. **Gitleaks** (generic security test `gitleaks`): completes without clone or runner faults—no `ERROR_CLONING`, `ERROR_TIMEOUT_GITLEAKS`, or `ERROR_RUNNING_GITLEAKS`; output is valid for the existing analyzer (JSON path as in `api/config.yaml`).
2. **Wiz CLI** (generic security test `wizcli`): completes without clone or auth faults—no `ERROR_CLONING`, `ERROR_AUTH_WIZCLI`; stdout is processed by `analyzeWizCLI` without that function returning an auth error.

Other work may still run in parallel (e.g. **gitauthors**, **enry**, language-specific tools for languages detected in the repo). Those are **not** part of this success definition unless they block the analysis (e.g. fatal error short-circuiting the run).

## Architecture (unchanged from stock compose)

- **`dockerapi`**: `docker:24-rc-dind`, privileged, Docker API on TCP `2376`, TLS assets under `deployments/certs`.
- **`api`**: `HUSKYCI_INFRASTRUCTURE_USE=docker`, connects to DinD, upserts security tests into Mongo at startup (see caveat below), orchestrates scanner containers **on the DinD daemon** (no bind-mount of `~/Gits/deployment-catalog` from the Mac).
- **`huskyci-client`**: `POST /analysis` with `HUSKYCI_CLIENT_REPO_URL`, `HUSKYCI_CLIENT_REPO_BRANCH`, `HUSKYCI_CLIENT_API_ADDR`, and a **Husky-Token** minted for the **same** repository URL as used in the analysis request.

## Prerequisites

### Repository

- A **cloneable** HTTPS or SSH URL and branch for `deployment-catalog` (must match the URL used when minting the Husky token).
- For private remotes: configure **`GIT_PRIVATE_SSH_KEY`** (or documented substitute) so scanner images can clone, consistent with existing HuskyCI docs.

### Gitleaks

- DinD must reach the registry for **`huskyci/gitleaks`** (or set **`HUSKYCI_GITLEAKS_IMAGE`** / **`HUSKYCI_GITLEAKS_IMAGE_TAG`** on the API service to an image DinD can pull).

### Wiz CLI

- **API environment:** `HUSKYCI_API_WIZ_CLIENT_ID` and `HUSKYCI_API_WIZ_CLIENT_SECRET` must be set on the API process so `api/util.HandleCmd` can substitute `%WIZ_CLIENT_ID%` / `%WIZ_CLIENT_SECRET%` in the `wizcli` command from `api/config.yaml`.
- **Scanner image:** Default config points to **`939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz:latest`**. DinD must be able to **pull** that image (typically `aws ecr get-login-password` + `docker login` against the DinD host, or mirroring the image to a registry DinD can access without extra auth).
- **Wiz tenant:** The embedded policy name in config (`aai-secrets-default-policy`) must exist and be usable for the supplied service account, or the command in Mongo/config must be updated to a valid policy for your tenant.

### Product gap — Mongo seeding for `wizcli`

`wizcli` is defined under **`api/config.yaml`**, but **`wizcli` is not included** in `checkEachSecurityTest` in `api/util/api/api.go`, and there is no **`WizcliSecurityTest`** field in `api/context`’s `APIConfiguration` / `SetOnceConfig` wiring analogous to `GitleaksSecurityTest`.

On a **fresh** MongoDB volume, **`wizcli` may never be upserted**, so `getAllDefaultSecurityTests("Generic", "")` might not return Wiz and the e2e would not match the success criteria above.

**Resolution (implementation plan scope):** Add `wizcli` to the startup security-test upsert path (context + `checkSecurityTest` switch + `checkEachSecurityTest` list) so Mongo always contains a default generic `wizcli` row aligned with `api/config.yaml`. Until that lands, operators can **manually insert** a `securityTest` document for `wizcli` for one-off testing.

## Procedure summary (Approach 1)

1. Start **`deployments/docker-compose.yml`** from the `deployments/` directory; wait for Mongo health and API listening on **8888**.
2. Confirm **`GET /healthcheck`** and review API logs for requirement checks.
3. Mint a Husky token: **`POST /api/1.0/token`** with API basic auth; JSON body must include the **same `repositoryURL`** you will analyze.
4. Run **`huskyci-client`** with the client env vars pointing at `http://127.0.0.1:8888` (or the published host port) and the remote URL/branch for `deployment-catalog`.
5. Validate success via client output and/or **`GET /analysis/:RID`** JSON: inspect containers for **`gitleaks`** and **`wizcli`** (`CResult`, absence of error markers in captured output as above).

## Risks

- **First-run latency:** Many images pulled into DinD; clone depth and repo size affect wall time.
- **Apple Silicon:** Scanner images may require **`linux/amd64`**; document platform flags if pulls fail.
- **`wizcli` command uses `|| true`:** The shell may mask non-zero exit from `wizcli dir scan`; treat **auth and clone markers** plus **structured parse errors** as primary pass/fail signals, not only exit code.

## Out of scope

- Host bind-mount of `~/Gits/deployment-catalog` into scanners (not supported by current `CreateContainer` host config).
- Replacing DinD with host Docker for the API’s `docker` infrastructure mode (different test).

## Next step

After review of this document, produce an **implementation plan** (`writing-plans` skill): exact compose commands, token `curl` example, client env block, DinD ECR login flow, and the optional **`wizcli` Mongo upsert wiring** patch if still required.
