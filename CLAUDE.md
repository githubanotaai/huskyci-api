# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Three independent Go modules

`api/`, `client/`, and `cli/` are separate Go modules — each has its own `go.mod`, `go.sum`, and `.golangci.yml`. You must `cd` into the relevant module to run `go` commands. Forgetting this is the #1 source of confusion.

```sh
cd api && go test -race ./...                     # run a module's tests
cd api && go test -race -run TestCheckMalicious ./util  # single test
cd api && go vet ./... && go build ./...
cd api && golangci-lint run ./...                 # linter is v2.x with .golangci.yml per module
```

CI mirrors this layout: a matrix job runs vet/build/test against each of `api`, `client`, `cli` (Go 1.23) plus a separate `golangci-lint` job per module. See `.github/workflows/ci.yaml`.

The linter config suppresses `ST*` (stylecheck) rules because the codebase has legacy naming conventions that are too invasive to fix safely (`api/.golangci.yml`). New code should still follow Go conventions; lowercase error strings without trailing punctuation.

## Architecture: three-tier scan orchestration

```
huskyci-client (in CI runner pod)
   │ POST /analysis  { repositoryURL, repositoryBranch, languageExclusions, changedFiles }
   ▼
huskyci-api (Echo HTTP server on :8888)
   │ creates pods/containers per security tool
   ▼
Scanner pods/containers (enry, bandit, gosec, gitleaks, npm/yarn/pnpm audit, wizcli, …)
   │ each clones the target repo, runs its tool, emits JSON on stdout
   ▼
API collects stdout, parses JSON per-tool, persists to MongoDB
   │
huskyci-client polls GET /analysis/:id, prints results, writes SonarQube JSON,
   exits 190 if HIGH/MEDIUM vulns were found
```

Entrypoints: `api/server.go`, `client/cmd/main.go`, `cli/main.go`. Routes are wired in `api/routes/`. The Echo group `/api/1.0` requires basic auth (`HUSKYCI_API_DEFAULT_USERNAME/PASSWORD`); `/analysis*` use a custom `Husky-Token` header validated by `api/token`.

### How a scan actually runs (analysis pipeline)

`api/analysis/analysis.go::StartAnalysis` runs `enry` first to detect languages in the repo, then fans out two `errgroup.Group`s in `api/securitytest/run.go`:

- `runGenericScans` — runs all `type: Generic` tests (enry, gitauthors, gitleaks, wizcli_*)
- `runLanguageScans` — for each language enry found, runs each `type: Language` test whose `language:` matches (gosec, bandit, npmaudit, …)

Each scan's lifecycle is driven by `SecTestScanInfo.Start()` in `api/securitytest/securitytest.go`:
1. Substitute placeholders in `cmd` (`HandleCmd`, `HandleGitURLSubstitution`, `HandlePrivateSSHKey` in `api/util/util.go`).
2. Run the container — `kubeRun` (`api/kubernetes/`) or `dockerRun` (`api/dockers/`), chosen by `HUSKYCI_INFRASTRUCTURE_USE` (`kubernetes` or `docker`).
3. Capture stdout into `Container.COutput`.
4. Call `securityTestAnalyze[name]` — one of the per-tool `analyze*` functions in `api/securitytest/<tool>.go`, which parses the JSON the tool wrote to stdout and populates `scan.Vulnerabilities`.
5. `setVulns` merges that scan's vulns into the right field of `RunAllInfo.HuskyCIResults` (mapped in `vulnOutput`).

The `scanRunner` interface in `api/securitytest/runner.go` lets tests substitute `mockRunner` for DB + container execution — use it when adding tests that exercise `runGenericScans`/`runLanguageScans`.

### Adding a new scanner — checklist

A new scanner is not a single-file change. Touch all of:

1. `api/config.yaml` — add the YAML block with `name`, `image`, `imageTag`, `cmd`, `type` (`Generic` or `Language`), `language` (if Language), `default`, `timeOutInSeconds`. The `cmd` is a shell script with `%GIT_REPO%`, `%GIT_BRANCH%`, `%GIT_PRIVATE_SSH_KEY%`, `%CHANGED_FILES%`, and optionally `%WIZ_CLIENT_ID%`/`%WIZ_CLIENT_SECRET%` placeholders.
2. `api/context/context.go` — add a `*types.SecurityTest` field to `APIConfig` and a `getSecurityTestConfig("name")` call in `SetOnceConfig`.
3. `api/securitytest/securitytest.go` — register `"name": analyzeFoo` in `securityTestAnalyze`.
4. `api/securitytest/foo.go` — implement `analyzeFoo(scanInfo *SecTestScanInfo) error` that unmarshals `scanInfo.Container.COutput` and appends to `scanInfo.Vulnerabilities.{High,Medium,Low}Vulns`.
5. `api/securitytest/run.go` — add a `case` in `vulnOutput` returning a pointer into `HuskyCIResults`.
6. `api/types/types.go` — extend `HuskyCIResults` / its sub-structs if the language group is new.
7. The scanner config must also be seeded into MongoDB at deploy time — `getAllDefaultSecurityTests` reads from the `securityTest` collection, not from `config.yaml` directly.

### Delta scanning

When the client passes `changedFiles` (newline-separated paths) and the API sets `HUSKYCI_DELTA_SCAN=true` for a scanner via `HUSKYCI_SCANNER_<NAME>_DELTA_SCAN`, scanner `cmd` blocks take the sparse-checkout branch: `git clone --no-checkout` + `git sparse-checkout add` per file + `git checkout --`. If you edit the sparse-checkout shell blocks in `config.yaml`, **all** scanner blocks (bandit, gosec, gitleaks, wizcli_*) follow the same pattern — keep them in sync, and preserve the `ERROR_SPARSE_CHECKOUT` sentinel since `analyze()` in `securitytest.go` matches it. `changedFiles` is validated by `util.CheckMaliciousChangedFiles` to block shell metacharacters before it ever reaches the container.

### Disabling tests at runtime

`HUSKYCI_DISABLE_<TESTNAME>=true` (e.g. `HUSKYCI_DISABLE_GITLEAKS`) is checked by `isTestDisabled` in `run.go` before each scan starts — useful for cost/incident response without redeploying.

## Database

MongoDB is the supported production store (`api/db/mongo/mongo.go`). `db.Requests` (`api/db/huskydb.go`) is the interface for database operations, preserved for abstraction and testability.

## Local dev environment

`make compose` brings up the Docker-mode stack (API + MongoDB + dockerd-in-docker for scanner containers) via `deployments/docker-compose.yml`. `make install` runs `create-certs` → `compose` → `generate-passwords`. The K8s mode requires a real cluster; no docker-compose path exists for it.

## CI contracts beyond unit tests

`.github/workflows/ci.yaml` also enforces two contracts the unit suite can't:

- **Gitleaks v8 + fixture finding.** Builds `deployments/dockerfiles/gitleaks/Dockerfile`, asserts the binary reports `v8.x`, then runs it on `api/securitytest/testdata/gitleaks_e2e_fixture` expecting **exactly one** finding with `RuleID: "github-pat"`. If you change the fixture or the gitleaks image, update both ends.
- **Deployment shell `bash -n`.** `deployments/scripts/verify-depl-scripts.sh` syntax-checks the registry/push scripts. No registries are pushed from CI.

## Exit codes from the client

`190` is intentional and load-bearing: it tells the GitHub Action that the scan ran successfully but found blocking (HIGH/MEDIUM) vulnerabilities. Do not collapse it into `1` — operators distinguish "scan failed" from "scan found bugs" using this code.
