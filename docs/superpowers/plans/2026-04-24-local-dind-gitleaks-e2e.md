# Local DinD Gitleaks e2e (`deployment-catalog`) — Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run HuskyCI locally with the stock **Docker-in-Docker** stack, drive one analysis with **huskyci-client** against a **remote Git URL** (e.g. `deployment-catalog`), and confirm **Gitleaks** completes successfully per [docs/superpowers/specs/2026-04-24-local-dind-deployment-catalog-e2e-design.md](../specs/2026-04-24-local-dind-deployment-catalog-e2e-design.md).

**Architecture:** `deployments/docker-compose.yml` starts MongoDB, `dockerapi` (DinD on TCP 2376), and the API (`HUSKYCI_INFRASTRUCTURE_USE=docker`). The API schedules scanner containers on the **DinD** daemon; clones use the repository URL from the analysis request. Success for this plan means the **gitleaks** container has no `ERROR_CLONING`, `ERROR_TIMEOUT_GITLEAKS`, or `ERROR_RUNNING_GITLEAKS` in its captured output and `CResult` reflects completion as expected by the API.

**Tech stack:** Docker Compose, Go (`huskyci-client`), `curl`, MongoDB shell (optional), HuskyCI API on port **8888**.

**Design reference:** [2026-04-24-local-dind-deployment-catalog-e2e-design.md](../specs/2026-04-24-local-dind-deployment-catalog-e2e-design.md) (Gitleaks-only; Wiz out of scope).

---

## File / component map

| Path | Role |
|------|------|
| [deployments/docker-compose.yml](../../deployments/docker-compose.yml) | Defines `dockerapi`, `api`, `mongodb`; API env for DB and DinD. |
| [deployments/certs/](../../deployments/certs/) | TLS PEMs mounted into API; DinD TLS config under `../deployments/certs` in compose. |
| [api/config.yaml](../../api/config.yaml) | Default `gitleaks` image (`huskyci/gitleaks`) and `cmd` (clone + `gitleaks dir`). |
| [api/context/context.go](../../api/context/context.go) | `HUSKYCI_GITLEAKS_IMAGE` / `HUSKYCI_GITLEAKS_IMAGE_TAG` override Gitleaks image for the API process. |
| [client/cmd/main.go](../../client/cmd/main.go) | `huskyci-client` entrypoint: start analysis, poll, print results. |
| [client/config/config.go](../../client/config/config.go) | Reads `HUSKYCI_CLIENT_*` and `HUSKYCI_LANGUAGE_EXCLUSIONS`. |
| [api/routes/analysis.go](../../api/routes/analysis.go) | `POST /analysis`, `GET /analysis/:id`; `Husky-Token` header. |
| [api/token/tokenvalidator.go](../../api/token/tokenvalidator.go) | If **no** valid access token row exists for the repo URL, `HasAuthorization` returns **true** without a token; once a token exists for that URL, requests must send a valid token. |

No repository code changes are required for the happy path; this plan is **operator runbook** steps.

---

### Task 1: Preconditions and variables

**Files:** None (shell only).

- [ ] **Step 1: Clone / open repo and pick identifiers**

From the machine that runs Docker:

```bash
cd /path/to/huskyci-api   # e.g. /Users/you/Gits/huskyci-api
export HUSKY_REPO_URL='https://github.com/your-org/deployment-catalog.git'   # MUST match token mint URL after normalization
export HUSKY_BRANCH='main'    # or your default branch
```

Use the **canonical HTTPS URL** you will use in both token mint and client env. Avoid trailing-slash mismatches vs what the API stores after `ValidateURL`.

- [ ] **Step 2: Decide SSH key for private Git**

For **public** repos, you may leave `HUSKYCI_API_GIT_PRIVATE_SSH_KEY` unset; scanner commands still write the placeholder into `~/.ssh/huskyci_id_rsa` (may be empty).

For **private** SSH clones (`git@github.com:...`), set a **single-line** PEM or the API’s normal convention for multiline keys (see tests in [api/util/util_test.go](../../api/util/util_test.go) around `HUSKYCI_API_GIT_PRIVATE_SSH_KEY`).

- [ ] **Step 3: Confirm Docker resources**

Docker Desktop (or Linux Docker) with enough disk for DinD image pulls (`huskyci/enry`, `huskyci/gitauthors`, `huskyci/gitleaks`, plus any language scanners **enry** detects in `deployment-catalog`). On **Apple Silicon**, if pulls fail with wrong architecture, add DinD / API `platform: linux/amd64` in a local **override** compose file (not committed unless the team agrees).

---

### Task 2: Ensure `wizcli` does not fail generic scans

**Files:** None, or temporary compose override.

- [ ] **Step 1: After first stack boot, inspect Mongo for `wizcli`**

With compose running (Task 3), from the host:

```bash
cd /path/to/huskyci-api/deployments
docker compose exec -T mongodb mongo huskyCIDB -u huskyCIUser -p huskyCIPassword --authenticationDatabase admin --quiet --eval 'db.securityTest.find({name:"wizcli"},{name:1,default:1,type:1}).pretty()'
```

**Expected outcomes:**

- **No document:** Wiz will not run; OK for Gitleaks-only e2e.
- **Document with `default: false`:** Wiz will not run; OK.
- **Document with `default: true`:** Wiz **will** run; fix before relying on Gitleaks-only success (set `default: false` with an update, or use a fresh `mongo_vol`).

- [ ] **Step 2: If needed, disable `wizcli` in Mongo**

```bash
docker compose exec -T mongodb mongo huskyCIDB -u huskyCIUser -p huskyCIPassword --authenticationDatabase admin --quiet --eval 'db.securityTest.updateOne({name:"wizcli"},{$set:{default:false}})'
```

Verify with the `find` from Step 1.

---

### Task 3: Start the stack

**Files:** [deployments/docker-compose.yml](../../deployments/docker-compose.yml) (read-only unless you add a local override).

- [ ] **Step 1: Start services from `deployments/`**

```bash
cd /path/to/huskyci-api/deployments
docker compose up --build -d
```

Wait until `mongodb` is healthy and `api` stays up (first build can take several minutes).

- [ ] **Step 2: Tail API logs until server listens**

```bash
docker compose logs -f api
```

Look for successful **CheckHuskyRequirements** / absence of fatal `SERVER` errors. Stop tailing with Ctrl+C when stable.

- [ ] **Step 3: Health check from host**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8888/healthcheck
```

**Expected:** `200`

---

### Task 4: (Optional) Point Gitleaks at a custom image

**Files:** None; use compose `environment` override or `docker compose run` with `-e` on a one-off API container — simplest is a **compose override file** not committed, e.g. `deployments/docker-compose.override.yml`:

```yaml
services:
  api:
    environment:
      HUSKYCI_GITLEAKS_IMAGE: huskyci/gitleaks
      HUSKYCI_GITLEAKS_IMAGE_TAG: "8.30.1"
```

Then `docker compose up -d` again. Match tags to [api/config.yaml](../../api/config.yaml) defaults unless you intentionally test a custom build from [deployments/dockerfiles/gitleaks/Dockerfile](../../deployments/dockerfiles/gitleaks/Dockerfile).

- [ ] **Step 1:** Only if DinD cannot reach Docker Hub or you need a pinned local build; otherwise skip.

---

### Task 5: Mint Husky token

**Files:** None (`curl` only).

- [ ] **Step 1: Request token with API basic auth**

Default compose credentials ([deployments/docker-compose.yml](../../deployments/docker-compose.yml)):

- Username: `huskyCIUser`
- Password: `huskyCIPassword`

```bash
export HUSKY_TOKEN="$(
  curl -sS -u 'huskyCIUser:huskyCIPassword' \
    -H 'Content-Type: application/json' \
    -X POST 'http://127.0.0.1:8888/api/1.0/token' \
    -d "{\"repositoryURL\":\"${HUSKY_REPO_URL}\"}" \
  | jq -r '.huskytoken // empty'
)"
echo "Token length: ${#HUSKY_TOKEN}"
```

**Expected:** Non-empty `HUSKY_TOKEN` (JSON field `huskytoken` from `201 Created` response). If `jq` prints nothing, print raw response for debugging:

```bash
curl -sS -u 'huskyCIUser:huskyCIPassword' -H 'Content-Type: application/json' \
  -X POST 'http://127.0.0.1:8888/api/1.0/token' \
  -d "{\"repositoryURL\":\"${HUSKY_REPO_URL}\"}"
```

---

### Task 6: Build and run `huskyci-client`

**Files:** [client/cmd/main.go](../../client/cmd/main.go) (build artifact only).

- [ ] **Step 1: Build the client binary**

```bash
cd /path/to/huskyci-api/client/cmd
go build -o huskyci-client main.go
```

**Expected:** `huskyci-client` binary appears in `client/cmd/`.

- [ ] **Step 2: Export client environment**

```bash
export HUSKYCI_CLIENT_API_ADDR='http://127.0.0.1:8888'
export HUSKYCI_CLIENT_REPO_URL="${HUSKY_REPO_URL}"
export HUSKYCI_CLIENT_REPO_BRANCH="${HUSKY_BRANCH}"
export HUSKYCI_CLIENT_TOKEN="${HUSKY_TOKEN}"
# TLS off for local compose (default)
unset HUSKYCI_CLIENT_API_USE_HTTPS
```

- [ ] **Step 3: (Optional) Skip language scanners if they break the run**

`HUSKYCI_LANGUAGE_EXCLUSIONS` is a comma-separated list of **enry language keys** (JSON object keys from enry output, e.g. `Go`, `Python`, `JavaScript`). Example:

```bash
export HUSKYCI_LANGUAGE_EXCLUSIONS='Go,Python,JavaScript,Java,Ruby,HCL,Shell,YAML,JSON,Markdown'
```

Tune after inspecting a failed analysis’s **enry** `COutput` in `GET /analysis/:RID`. If you exclude **all** languages enry reports, `runLanguageScans` schedules nothing.

- [ ] **Step 4: Run the client**

```bash
cd /path/to/huskyci-api/client/cmd
./huskyci-client
```

**Expected:** Client prints started RID, polls until completion, then lists per-container results. Exit code `0` or `1` depends on vuln detection ([client/cmd/main.go](../../client/cmd/main.go)); for **infrastructure** success, do not rely only on exit code—inspect Gitleaks output (Task 7).

---

### Task 7: Verify Gitleaks success

**Files:** None.

- [ ] **Step 1: Note RID from client output**

Example line: `[HUSKYCI][*] huskyCI analysis started! RID: <uuid>`.

```bash
export RID='<paste-RID-here>'
```

- [ ] **Step 2: Fetch analysis JSON**

```bash
curl -sS -H "Husky-Token: ${HUSKY_TOKEN}" \
  "http://127.0.0.1:8888/analysis/${RID}" | jq '.' > /tmp/husky-analysis.json
```

- [ ] **Step 3: Locate `gitleaks` container**

```bash
jq '.containers[] | select(.securityTest.name=="gitleaks") | {CResult, COutput: .COutput}' /tmp/husky-analysis.json
```

**Pass criteria for Gitleaks:**

- `CResult` is a completed state used by your deployment (commonly `finished` or similar—compare other passing containers in the same JSON).
- `COutput` does **not** contain: `ERROR_CLONING`, `ERROR_TIMEOUT_GITLEAKS`, `ERROR_RUNNING_GITLEAKS`.

Quick grep:

```bash
jq -r '.containers[] | select(.securityTest.name=="gitleaks") | .COutput' /tmp/husky-analysis.json | grep -E 'ERROR_CLONING|ERROR_TIMEOUT_GITLEAKS|ERROR_RUNNING_GITLEAKS' && echo 'FAIL markers found' || echo 'No Gitleaks hard-error markers'
```

**Expected:** `No Gitleaks hard-error markers`.

- [ ] **Step 4: (Optional) Pretty-print Gitleaks JSON findings**

When successful, `COutput` often contains JSON from `gitleaks` (may be empty array `[]`). Validate parseability:

```bash
jq -r '.containers[] | select(.securityTest.name=="gitleaks") | .COutput' /tmp/husky-analysis.json | jq -e 'type=="array"' >/dev/null && echo 'Parsed as JSON array' || echo 'Output is not a simple JSON array (inspect manually)'
```

---

### Task 8: Teardown and cleanup

- [ ] **Step 1: Stop stack**

```bash
cd /path/to/huskyci-api/deployments
docker compose down
```

- [ ] **Step 2: Remove volumes only if you want a clean Mongo/DinD state next time**

```bash
docker compose down -v
```

**Warning:** `-v` deletes `mongo_vol` and `docker_vol` (cached images in DinD).

---

## Commands reference (copy-paste block)

Replace `HUSKY_REPO_URL` / `HUSKY_BRANCH` once at the top of a shell session:

```bash
export HUSKY_REPO_URL='https://github.com/your-org/deployment-catalog.git'
export HUSKY_BRANCH='main'
cd /path/to/huskyci-api/deployments
docker compose up --build -d
curl -sS -o /dev/null -w 'healthcheck: %{http_code}\n' http://127.0.0.1:8888/healthcheck

export HUSKY_TOKEN="$(curl -sS -u 'huskyCIUser:huskyCIPassword' -H 'Content-Type: application/json' \
  -X POST 'http://127.0.0.1:8888/api/1.0/token' \
  -d "{\"repositoryURL\":\"${HUSKY_REPO_URL}\"}" | jq -r '.huskytoken')"

cd /path/to/huskyci-api/client/cmd
go build -o huskyci-client main.go
export HUSKYCI_CLIENT_API_ADDR='http://127.0.0.1:8888'
export HUSKYCI_CLIENT_REPO_URL="${HUSKY_REPO_URL}"
export HUSKYCI_CLIENT_REPO_BRANCH="${HUSKY_BRANCH}"
export HUSKYCI_CLIENT_TOKEN="${HUSKY_TOKEN}"
./huskyci-client
```

Then run Task 7 `curl` / `jq` with the printed `RID`.

---

## Plan self-review

1. **Spec coverage:** Preconditions (remote URL, Gitleaks image pull, optional SSH key), Approach 1 (compose + client), Gitleaks-only success, `wizcli` isolation, language-scan risk (`HUSKYCI_LANGUAGE_EXCLUSIONS`), teardown — all mapped to tasks above. Wiz remains explicitly out of scope per design update.
2. **Placeholder scan:** No `TBD` / `TODO`; repo URL uses placeholder **your-org** as a concrete pattern to replace.
3. **Consistency:** `repositoryURL` / `HUSKYCI_CLIENT_REPO_URL` must match token mint; `Husky-Token` header matches minted token; compose basic auth matches [deployments/docker-compose.yml](../../deployments/docker-compose.yml).

---

## Success checklist (summary)

- [ ] `/healthcheck` returns **200**.
- [ ] `wizcli` not running as `default: true` generic (Task 2), unless you intentionally expand scope.
- [ ] `huskyci-client` completes polling without analysis-level fatal error attributable to **Gitleaks**.
- [ ] `GET /analysis/:RID` shows **gitleaks** without `ERROR_CLONING` / `ERROR_TIMEOUT_GITLEAKS` / `ERROR_RUNNING_GITLEAKS`.

---

**Plan complete and saved to** `docs/superpowers/plans/2026-04-24-local-dind-gitleaks-e2e.md`.

**Two execution options:**

1. **Subagent-driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration (**superpowers:subagent-driven-development**).
2. **Inline execution** — Run the checklist in this session with checkpoints (**superpowers:executing-plans**).

Which approach do you want for execution?
