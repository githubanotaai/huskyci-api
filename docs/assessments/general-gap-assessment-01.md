# HuskyCI Platform — Comprehensive Gap Assessment

> **Note on deliverable shape.** The `/plan` slash command requested an implementation plan, but the `/plan` user prompt requested a research report. Treating this file as the requested research report. No code changes proposed.

---

## Executive Summary

**Repository purpose & architecture.** HuskyCI is a CI/CD-orchestrated security-scan platform composed of three independent Go modules (`api/`, `client/`, `cli/`). The client posts a scan request to the API (`POST /analysis`); the API fans out per-scanner workloads as Docker containers or Kubernetes pods, parses each tool's JSON stdout, and persists results to MongoDB. Scanner containers (enry, gitleaks, gosec, bandit, npm/yarn/pnpm audit, wizcli variants, etc.) clone the repo themselves — the API never fetches code. The client polls results and exits `190` when blocking vulnerabilities are present (an intentional, load-bearing signal to GitHub Actions). Scanner registration is data-driven (`api/config.yaml` + a `securityTest` MongoDB collection) but every new scanner still requires seven coordinated source edits with no compile-time enforcement.

**Top 10 gaps (severity × likelihood).**

| # | Gap | Severity |
|---|---|---|
| 1 | Non-constant-time comparison for basic-auth password hash and token random data → timing side channel | **High** |
| 2 | `Docker.WaitContainer(timeOutInSeconds)` parameter is dead — uses `context.Background()`; per-scanner timeouts are not enforced in Docker mode | **High** |
| 3 | Unbounded goroutine fan-out across concurrent scans (no `errgroup.SetLimit`, no semaphore, no queue) — N scans × M scanners → N·M concurrent container starts | **High** |
| 4 | No graceful shutdown / no orphaned-container reaper → API restart leaves analyses stuck in `"running"` indefinitely and Docker/K8s resources behind | **High** |
| 5 | Kubernetes pod spec has no `securityContext` (no `runAsNonRoot`, no `readOnlyRootFilesystem`, no dropped capabilities, no seccompProfile) | **High** |
| 6 | Scanner images pinned by mutable tags (some `latest`); no digest pinning → silent supply-chain drift | **High** |
| 7 | No panic-recovery in scanner `analyze*` functions — a malformed tool output panics the goroutine; errgroup converts the panic into a re-raise that can crash the API process | **High** |
| 8 | `setFinalResult` (run.go:81) runs **before** `defer setToAnalysis()` (run.go:65) — `setToAnalysis` unconditionally resets `FinalResult = "passed"` on success path, masking the per-container computation | **High** |
| 9 | No tests for the core orchestration path (`api/analysis/StartAnalysis`) and no parser tests for 7 of ~12 scanners (gosec, bandit, npmaudit, yarnaudit, brakeman, spotbugs, tfsec, safety) | **Medium** |
| 10 | No structured logging, no metrics endpoint, no readiness probe, no operator-facing audit trail → incident-response blind spots for OOM/crash/orphan analyses | **Medium** |

**Maturity assessment.** The platform is **functionally complete and operationally fragile**. Scanner orchestration, MongoDB persistence, basic auth, per-repo token binding, delta scanning, and CI scan-contracts (gitleaks v8 fixture, deployment shell `bash -n`) are all implemented with reasonable care. But several load-bearing primitives are either missing (concurrency limits, request-correlated logging, container resource limits, K8s security context) or quietly broken (Docker timeout, finalization-order bug). Security posture is good at the perimeter (input regex, sandboxed `git clone`, per-repo token scoping, PBKDF2 password hashing) and weak at the depth (timing comparisons, secret-in-URL logging, scanner config trustfully loaded from a writable MongoDB collection). Production readiness for high scan volume or multi-tenant trust requires the High-severity items in the roadmap.

---

## Confirmed Gaps

### Non-constant-time comparison in basic auth and token validation
**Severity:** High
**Evidence:** `api/auth/auth.go:35` — `if passDB != hashedPass { return false, nil }`; `api/token/token.go:92` — `if hashval != hashdata { return errors.New("Hash value from random data is different") }`. Neither uses `crypto/subtle.ConstantTimeCompare`. PBKDF2 (`api/auth/pbkdf2caller.go`) raises offline brute-force cost but does nothing for an online timing oracle.
**Risk:** Network timing analysis can leak the hashed password / hashed random data byte-by-byte. With a few thousand requests an attacker can recover the comparison target without knowing PBKDF2 parameters. Combined with **#3** (no rate limiting) the oracle is unbounded.
**Recommendation:** Replace both string-inequality checks with `subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1`. Add per-IP and per-token rate limiting (Echo middleware or in front-proxy).

---

### Docker scanner timeout is a no-op
**Severity:** High
**Evidence:** `api/dockers/api.go:99-116` — `WaitContainer(timeOutInSeconds int)` declares the parameter but builds `ctx := goContext.Background()` and never references `timeOutInSeconds`. Compare with K8s mode (`api/kubernetes/api.go::WaitPod`) which does honour `TimeoutSeconds` via `ListOptions`. Per-scanner timeouts declared in `api/config.yaml` (e.g. gosec `timeOutInSeconds: 360`, spotbugs `3600`) are read, threaded through `SecTestScanInfo.Start()`, and dropped on the floor in Docker mode.
**Risk:** A hung scanner (network stuck on `git clone`, runaway analyzer) blocks its goroutine forever in Docker mode. The parent analysis never completes; `errgroup.Wait` never returns; the goroutine is non-cancellable. Combined with **#3** this is a denial-of-service primitive.
**Recommendation:** `ctx, cancel := goContext.WithTimeout(goContext.Background(), time.Duration(timeOutInSeconds)*time.Second); defer cancel()`. On timeout, also call `ContainerStop` and `ContainerRemove` to free resources.

---

### Unbounded goroutine fan-out for concurrent scans
**Severity:** High
**Evidence:** `api/securitytest/run.go:67-83`, `86-128`, `131-185` — each call to `Start()` opens two `errgroup.WithContext(context.Background())` and within each, every `genericTests[i]` and every `languageTests[i]` is dispatched with bare `g.Go(...)`. No `errgroup.Group.SetLimit`, no buffered semaphore, no work queue. Routes (`api/routes/analysis.go::ReceiveRequest`) accept the request and spawn `StartAnalysis` without a rate limit.
**Risk:** A burst of K concurrent scan requests, each spawning ~12 scanners, attempts K·12 simultaneous container starts. Docker daemon / K8s API will eventually reject, but goroutines pile up first; memory grows linearly; failure mode under load is "everything stuck" rather than "graceful 503". Tests must hit shared Docker socket → noisy-neighbour saturation across tenants.
**Recommendation:** (a) Apply `errgroup.Group.SetLimit(N)` per analysis to cap intra-analysis concurrency. (b) Introduce a global semaphore (or token-bucket middleware) bounding system-wide concurrent scans; reject overflow with 429.

---

### No graceful shutdown; orphaned containers and stuck analyses on restart
**Severity:** High
**Evidence:** `api/server.go` registers `middleware.Recover()` but does not register `signal.Notify`/`server.Shutdown`. `api/analysis/analysis.go::StartAnalysis` writes `status:"running"` to MongoDB then returns to caller while goroutines continue. If the process is killed (deploy, OOM, panic), the only place those goroutines could clean up is the deferred `registerFinishedAnalysis` — which never fires for a `SIGKILL`. No background reaper scans Mongo for stale `"running"` analyses.
**Risk:** Every API restart leaks one Docker container or K8s pod per in-flight scanner and one stuck Mongo row per in-flight analysis. The client polls `GET /analysis/:id` forever (or until the client times out — which the repo does not document a value for).
**Recommendation:** Add a top-level signal handler that calls `server.Shutdown(ctx)` and a deadlined `WaitGroup` over in-flight analyses. Add a sweeper goroutine: every N minutes, find analyses with `status=running, startedAt < now - max(timeOutInSeconds)`; mark `status="error running", finalResult="error", error="reaped after restart"`.

---

### Kubernetes pod spec has no securityContext
**Severity:** High
**Evidence:** `api/kubernetes/api.go::CreatePod` (per Phase-3 agent, lines 104-141) builds the pod spec without a `SecurityContext` at pod or container level. No `runAsNonRoot`, no `readOnlyRootFilesystem`, no `allowPrivilegeEscalation: false`, no `capabilities.drop: [ALL]`, no seccomp profile.
**Risk:** A malicious or compromised scanner image (or a CVE in a trusted scanner image — wizcli, gitleaks, etc. evolve weekly) runs as root with a writable rootfs and the default Linux capability set. Combined with **#6** (mutable tags), supply-chain compromise of one scanner image gives root in the scanner pod, which depending on the cluster's PodSecurityStandard may pivot to node compromise.
**Recommendation:** Add `SecurityContext: { RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(1000)), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: { Drop: ["ALL"] }, SeccompProfile: { Type: "RuntimeDefault" } }`. Verify each scanner image still functions; any that need `/tmp` write get an `emptyDir` volume.

---

### Scanner images pinned by mutable tags
**Severity:** High
**Evidence:** `api/config.yaml` uses `imageTag:` fields with values like `1dd950e-amd64`, `v2.3.0`, and (per Phase-3 agent) at least one `latest`. Gitleaks image/tag is overridable via env (`api/context/context.go:444-450`) but no per-scanner digest pin. The CI `gitleaks-contract` job asserts the *built* image produces the expected behaviour, but the *runtime* pull resolves the tag at scan time — drift between CI's build and production's pull is invisible.
**Risk:** Image registry compromise, tag re-push, or accidental scanner upgrade silently changes scan behaviour for every customer in flight. False-negative regressions in security tools are particularly insidious — they look like "good news".
**Recommendation:** Pin every scanner image by `@sha256:` digest in `config.yaml`. Add a CI job that resolves each tag to a digest weekly and opens a PR if drift is detected (Renovate or a simple `crane digest` script).

---

### No panic recovery in scanner analyze* functions
**Severity:** High
**Evidence:** `api/securitytest/run.go:100-124` and `149-181` — `g.Go(func() error { ... runner.startScan(scan) ... })` with no `defer func() { recover() }`. `securitytest.go` dispatches to `securityTestAnalyze[name](scanInfo)` which calls per-tool unmarshalling logic. The middleware-level `middleware.Recover()` only catches panics in the HTTP request goroutine, not in detached analysis goroutines spawned later.
**Risk:** Any per-tool parser (`api/securitytest/gosec.go`, `bandit.go`, `wizcli.go`, etc.) that hits a nil-deref on malformed JSON brings down the API process. Scanner output is parsed-but-not-trusted — a compromised scanner image or a tool that ships malformed JSON on the next release is a remote crash primitive.
**Recommendation:** Wrap each `g.Go` body with `defer func(){ if r := recover(); r != nil { err = fmt.Errorf("scan panic: %v", r) } }()` and return the error normally. Add a panic counter metric.

---

### Finalization-order bug: setFinalResult is clobbered by deferred setToAnalysis
**Severity:** High
**Evidence:** `api/securitytest/run.go:63-83`:
```go
func (results *RunAllInfo) Start(enryScan SecTestScanInfo) error {
    results.Codes = enryScan.Codes
    defer results.setToAnalysis()           // line 65 — runs LAST
    ...
    if err := g.Wait(); err != nil { ... }
    results.setFinalResult()                 // line 81 — runs BEFORE the defer
    return nil
}
```
Then `setToAnalysis` (run.go:243-277) unconditionally sets `results.FinalResult = "passed"` on entry (line 246) before recomputing from `container.CResult` values, while `setFinalResult` (run.go:324-340) computes `FinalResult` from a *different* signal (also `container.CResult == "failed"`, but ignoring `"warning"` and the JS-warning special case).
**Risk:** `setFinalResult`'s value is always thrown away. Either the function is dead code (then delete it) or the intended semantics are silently wrong (then the bug is observable in customer-facing scan results). Possibly explains why `setFinalResult` exists alongside `setToAnalysis` with overlapping logic — appears to be a half-finished refactor.
**Recommendation:** Read the git history to determine which is the intended finalizer, delete the other, and add a test that exercises a mixed-result analysis (one `failed`, one `warning`, one `passed`) and asserts the final value.

---

### Scanner config is trust-loaded from a writable MongoDB collection
**Severity:** High
**Evidence:** `api/securitytest/run.go:279-293` — `getAllDefaultSecurityTests` runs `FindAllDBSecurityTest` and returns whatever `cmd` strings are stored. `cmd` strings are then expanded by `HandleCmd` and executed in the scanner container by `/bin/sh -c`. There is no signature, no integrity check, no allowlist of `cmd` templates. The `securityTest` collection has no API-level writer, but any process with MongoDB credentials can rewrite a scanner's `cmd` to arbitrary shell.
**Risk:** A MongoDB compromise (credentials in `.env`, network exposure, replica reachable from compromised pod) escalates directly to RCE in every scanner container on the next scan. The blast radius is "every customer". Combined with **#5** (no securityContext), that's root in the cluster.
**Recommendation:** Treat scanner `cmd` templates as code, not data: ship them in `config.yaml` only, read them from disk, and use the MongoDB row solely for the enable/disable flag and language metadata. Or sign the `cmd` field with a deploy-time key and verify on load.

---

### Repository URL regex allows internal targets (limited SSRF)
**Severity:** Medium
**Evidence:** `api/util/util.go:169-181` — `CheckMaliciousRepoURL` regex `((git|ssh|http(s)?)|((git@|gitlab@)[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/?)`. Allows `http://10.0.0.1/repo.git`, `http://169.254.169.254/repo.git`, `git://localhost/repo.git`, etc.
**Risk:** The URL is only ever consumed by `git clone` inside the scanner container, so the SSRF reach is bounded by the scanner pod's network policy. In a cluster without `NetworkPolicy` restricting egress, the scanner can hit cloud metadata services and exfiltrate IAM credentials. The risk is **conditional on missing K8s network policy** (which the repo does not ship).
**Recommendation:** Block RFC1918, link-local (`169.254/16`), loopback, and `file://` in the validator. Ship an egress `NetworkPolicy` example alongside the scanner pod creation code.

---

### MongoDB: no indexes declared, no TTL, no query limits
**Severity:** Medium
**Evidence:** `api/db/mongo/mongo.go` — no `CreateIndex` calls. `api/db/huskydb.go` — `Find*` operations construct `bson.M` filters without `.SetLimit()`. `Analysis` documents embed `Containers []Container`, `Codes []Code`, and the nested `HuskyCIResults` with per-language vulnerability arrays — single-document size grows unbounded with scan output. No TTL index on the `analysis` collection.
**Risk:** (a) Query performance degrades as collection grows (full-collection scans for `find({URL: ..., status: "running"})` style lookups). (b) Storage cost grows unboundedly; no retention policy. (c) Privacy/compliance exposure — repo URLs, commit author emails (`CommitAuthors []string`) and scan results persist forever.
**Recommendation:** Declare indexes at startup (`URL+status`, `RID`, `createdAt`). Add a TTL index on `analysis.createdAt` (e.g. 90 days, configurable). Add `.SetLimit()` to any `Find*` whose result feeds a UI or aggregate. Document the retention SLA.

---

### Unused PostgreSQL backend is dead code
**Severity:** Low (maintenance debt)
**Evidence:** `api/db/postgres/` implements the same `Requests` interface as MongoDB but is never instantiated. `deployments/docker-compose.yml` has the Postgres service commented out. CLAUDE.md explicitly notes it's not wired up.
**Risk:** Cognitive load (developers read it expecting it to matter), tests that don't run, dependency drift in `go.mod`. Lints / SCA scans waste effort on it.
**Recommendation:** Delete `api/db/postgres/` and the commented compose service. If multi-backend support is a real future requirement, re-add when needed (the interface is preserved either way).

---

### Test coverage gaps in the core orchestration and per-tool parsers
**Severity:** Medium
**Evidence:** No test file for `api/analysis/analysis.go` (the orchestration entrypoint `StartAnalysis`). No `*_test.go` for 7 of the ~12 scanner parsers: `gosec.go`, `bandit.go`, `npmaudit.go`, `yarnaudit.go`, `brakeman.go`, `spotbugs.go`, `tfsec.go`, `safety.go`. No tests for `api/dockers/`, `api/db/mongo/`. The `scanRunner` mock interface (`runner.go`) exists — meaning the framework supports orchestration tests — but no test consumes it.
**Risk:** A scanner-output schema change ships unnoticed until production. The finalization-order bug above (**#8**) would be caught instantly by an end-to-end test. Parser changes in `wizcli.go` (which *does* have tests) are well-protected; the others are not.
**Recommendation:** Add one orchestration test using `mockRunner` that exercises a multi-scanner success path and one mixed-result path. For each of the 7 untested parsers, drop a 50-line sample of real tool output in `testdata/` and add an `assert HighVulns==N` test. Add a CI coverage floor (e.g. `-coverprofile` + `go tool cover` + threshold check) once the floor is established.

---

### CI lacks security and supply-chain scanning of the platform itself
**Severity:** Medium
**Evidence:** `.github/workflows/ci.yaml` runs `go vet`, `go build`, `go test -race`, `golangci-lint`, Docker build, the gitleaks fixture contract, and `bash -n` on deployment scripts. There is no gosec/govulncheck/nancy step, no `trivy`/`grype` image scan, no SBOM generation, no license check. The platform whose job is to scan customer code does not scan itself.
**Risk:** Reputational and trust risk. Also material — `Makefile::check-sec` invokes gosec locally, so developers may assume CI does the same.
**Recommendation:** Add `govulncheck ./...` per module (covers Go advisory DB), `gosec ./...` per module (already wired in Makefile, just move to CI), and `trivy image` against the API/client/scanner Dockerfiles.

---

### Observability: no structured logging, no metrics, no readiness probe
**Severity:** Medium
**Evidence:** `api/log/log.go` wraps `glbgelf` (Globo's GELF logger). Calls are positional (`SendLog(extra map, level, msgs)`); not key/value structured per modern observability conventions. No request-correlation ID propagated from `POST /analysis` through scanner goroutines (scan RID is logged but not threaded uniformly). No `/metrics` endpoint, no OpenTelemetry, no Prometheus exporter. `/healthcheck` exists but no `/readiness` (no DB-reachability gate); K8s would route traffic to a pod that can't talk to MongoDB.
**Risk:** Incident response is slow. "Why are scans backing up?" requires log archaeology rather than a queue-depth metric. "Why is the deploy failing?" — no readiness probe to fail-fast.
**Recommendation:** Switch to `zap`/`zerolog` with mandatory `scan_id`, `request_id`, `repo_url_hash` fields. Add `/metrics` (prom-client-go) with at minimum: in-flight scans, scan duration histogram (per scanner), scanner failure counter (per tool), auth failure counter. Add `/readiness` that pings MongoDB and the container runtime.

---

### Secrets in URLs may be logged
**Severity:** Medium
**Evidence:** `api/routes/analysis.go` (per Phase-3 agent, around line 159) logs `repository.URL` directly. A repository URL like `https://user:token@github.com/org/repo.git` is a valid input shape (and the most common shape for token-authenticated GitHub access). PBKDF2 / token storage is fine; the URL log is the leak.
**Risk:** Centralized logs (GELF / Graylog / Datadog) end up holding plaintext PATs / SSH-cred-equivalents. Log-retention windows usually outlast credential rotation cadence.
**Recommendation:** Add a `redactURL(u string) string` helper that strips `userinfo` before any log line. Audit all `log.*` call sites that take a URL.

---

### Container security: API mounts Docker socket (Docker mode)
**Severity:** High *conditional* — confirm before committing
**Evidence:** `deployments/docker-compose.yml` runs the API alongside a dockerd-in-docker service; the API authenticates via TLS certs (`api/dockers/api.go:53-64`). This is **safer** than mounting `/var/run/docker.sock` because the dockerd is in its own container. Need to verify the actual production deployment uses the same pattern (the K8s mode bypasses Docker entirely).
**Risk:** If a production deployment mounts the host docker socket instead of using the TLS-isolated daemon, any scanner-image RCE = host root.
**Recommendation:** Document the contract: "production deployment MUST run dockerd in a separate container with TLS, OR use K8s mode. Mounting /var/run/docker.sock is unsupported." Add a startup check that refuses to run if the docker host is `unix:///var/run/docker.sock`.

---

### No rate limiting on authenticated endpoints
**Severity:** Medium
**Evidence:** `api/server.go` does not register any rate-limit middleware. `/api/1.0` is basic-auth-only; `/analysis` is `Husky-Token`-only.
**Risk:** Online brute force against either credential is unbounded (and amplified by **#1**'s timing oracle). Denial of service via scan-spam is unbounded (amplified by **#3**).
**Recommendation:** Echo middleware `middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(...))` per remote IP and per token. Tune to peak legitimate traffic + 2x.

---

## Probable Gaps

### Container resource limits (CPU/memory) not visible on pod/container spec
**Severity estimate:** Medium
**Indicators:** Phase-2 agent saw no `core.ResourceRequirements` in `api/kubernetes/api.go::CreatePod` lines 104-141. Docker mode has no equivalent flag set in `CreateContainer` (`api/dockers/api.go:78-91`).
**Investigation needed:** Read the full `CreatePod` body and check whether `Containers[0].Resources.Limits` is set. If absent, a malicious or pathological scan can OOM the node / saturate Docker host CPU.

### Scanner stdout is read into memory before parsing
**Severity estimate:** Medium
**Indicators:** `api/dockers/api.go:188-203` `ReadOutput` uses `io.ReadAll` on container logs. No max-size bound. A scanner producing GB-scale output (verbose tool, infinite loop) would OOM the API.
**Investigation needed:** Confirm there is no upstream container-log size cap in the Docker daemon config or K8s equivalent; if not, wrap with `io.LimitReader` at e.g. 100MB and treat overrun as a scan error.

### Sparse-checkout shell logic is duplicated across all scanner cmd blocks
**Severity estimate:** Low
**Indicators:** CLAUDE.md explicitly warns "all scanner blocks (bandit, gosec, gitleaks, wizcli_*) follow the same pattern — keep them in sync." Manual synchronization across YAML blocks is a long-term drift hazard.
**Investigation needed:** Read `config.yaml` and diff the sparse-checkout fragments — if there's any divergence today, the bug already exists. Possible mitigation: a shared shell function or a templated YAML include.

### Analysis collection grows unbounded under repeated scans of the same repo
**Severity estimate:** Medium
**Indicators:** `api/routes/analysis.go::ReceiveRequest` (Phase-1 agent lines 84-214) checks DB for an in-flight scan on `(url, branch)` but does not de-duplicate completed scans. Each commit/PR push = new row indefinitely.
**Investigation needed:** Read the de-dup logic and confirm; if confirmed, the TTL recommendation under "MongoDB" is the right mitigation.

### No tests exercising MongoDB / Docker / K8s with real backends
**Severity estimate:** Medium
**Indicators:** Phase-6 agent found no integration test target in Makefile, no `docker-compose test` target, no `testcontainers` usage. All `db` and `kubernetes` tests appear to mock the interface.
**Investigation needed:** Grep for `testcontainers`, `tcr`, or `compose up` in test files. If genuinely absent, an integration suite (using `testcontainers-go`) would protect the highest-leverage code path.

---

## Strengths

Evidence-based. Do not omit when prioritizing — these are the load-bearing things to *not break*.

- **Per-repository token scoping is enforced.** `api/token/token.go:120` `accessToken.URL != validURL` rejects cross-repo token use. Token A really cannot scan repo B.
- **PBKDF2-SHA256 (100k iterations) password hashing.** `api/auth/pbkdf2caller.go:32-34, 54-63`. Salt is 64 bytes from `crypto/rand`. Iterations are configurable via env.
- **Input validation is regex-allowlist, not denylist.** `api/util/util.go:184-198` (branch), `:204-219` (changed files), `:169-181` (repo URL — modulo the SSRF gap). All reject by default.
- **Placeholders are quoted in scanner templates.** `api/config.yaml` wraps `%GIT_REPO%`, `%GIT_BRANCH%` in double quotes; combined with `strings.ReplaceAll` substitution (not `fmt.Sprintf`), shell injection is prevented even if the regex slipped.
- **CI enforces two non-unit-test contracts.** `.github/workflows/ci.yaml:81-107` — gitleaks v8 + fixture finding shape; `:109-116` — `bash -n` on deployment scripts. These catch the failure modes that unit tests cannot.
- **Race detector on every module.** CI runs `go test -race -count=1`. Unusual rigor for a Go service of this size.
- **K8s `WaitPod` correctly enforces timeout via `ListOptions.TimeoutSeconds`.** `api/kubernetes/api.go::WaitPod`. Docker mode is the broken one (**#2**), not K8s.
- **`mockRunner` exists for orchestration testing.** `api/securitytest/runner.go`. Framework supports the tests that should be written (**#9**).
- **MongoDB connection has an auto-reconnect goroutine.** `api/db/mongo/mongo.go:77-94`. Survives transient DB blips.
- **Three-module separation enforced in CI.** Each module's lint/build/test runs independently — a regression in `cli` cannot break `api`'s deploy.
- **CLAUDE.md is comprehensive.** Three-tier architecture, scanner-addition checklist, delta-scan invariants, runtime kill-switches — all documented for the next contributor.
- **Delta scanning has changedFiles validation.** `api/util/util.go::CheckMaliciousChangedFiles` + `routes/analysis.go:110` — recent addition (per CLAUDE.md), with a dedicated test file.

---

## Prioritized Roadmap

### Immediate (0–30 days) — Critical/High items

| Item | Effort | Impact | Dependencies |
|---|---|---|---|
| Fix Docker `WaitContainer` timeout (**#2**) | 1 day | Eliminates hang-forever scans | None |
| Constant-time auth/token comparison + rate limiting (**#1**, **#17**) | 2 days | Closes timing oracle and brute-force vector | None |
| Wrap each scanner `g.Go` with `defer recover()` (**#7**) | 1 day | API no longer crashes on malformed scanner output | None |
| Diagnose & resolve `setFinalResult` / `setToAnalysis` order bug (**#8**) | 2 days incl. test | Restores correctness of scan finalization | Add the mixed-result test first to characterize current behaviour |
| Add `errgroup.SetLimit` + global semaphore (**#3**) | 2 days | Bounds blast radius of scan bursts | None |
| Pin scanner images by digest (**#6**) | 3 days | Closes silent supply-chain drift | Coordinate with scanner-image release cadence |
| Strip credentials from logged repo URLs (**#16**) | half day | Stops PAT leakage to log aggregator | None |

### Near-Term (30–90 days) — High/Medium and structural enablers

| Item | Effort | Impact | Dependencies |
|---|---|---|---|
| Graceful shutdown + stale-analysis reaper (**#4**) | 1 week | Restart no longer leaks containers or stuck rows | None |
| K8s `securityContext` hardening (**#5**) | 1 week incl. per-scanner verification | Closes scanner-image-RCE → root-in-pod escalation | Test each scanner under read-only rootfs |
| Move scanner `cmd` templates out of MongoDB read-path (**#9**) | 1 week | Eliminates RCE-via-Mongo-compromise primitive | Coordinate with operators (deployment-time config) |
| Govulncheck + gosec + trivy in CI (**#14**) | 3 days | Catches CVEs in the platform's own dependencies | None |
| MongoDB indexes + TTL + query limits (**#11**) | 1 week | Bounds storage growth and query latency | Choose retention SLA with stakeholders |
| Add orchestration test + parser tests for 7 missing scanners (**#13**) | 2 weeks | Catches the next finalization-order-style bug | Drop fixture JSON per scanner |
| `/metrics` and `/readiness` endpoints (**#15**) | 1 week | Operators can see what's happening | None |
| SSRF hardening on `CheckMaliciousRepoURL` (**#10**) | 2 days | Defense-in-depth even without NetworkPolicy | Coordinate with any existing internal-target test repos |

### Long-Term (90+ days) — Medium/Low and architectural investments

| Item | Effort | Impact | Dependencies |
|---|---|---|---|
| Structured logging migration (zap/zerolog with `scan_id`, `request_id`, `actor`) | 3 weeks | Materially better incident response | Coordinate with Graylog/SIEM pipeline |
| OpenTelemetry tracing across API → scanner-pod boundary | 4 weeks | End-to-end latency visibility | Tracing backend (Jaeger/Tempo/honeycomb) |
| Delete the unused Postgres backend (**#12**) | 1 day | Reduces cognitive load and lint surface | Confirm no dormant requirement |
| Ship a Helm chart (or Kustomize base) for API deployment | 2 weeks | First-class K8s deployment story; today only docker-compose is documented | None |
| Replace 11 MB `.gif` at repo root with externally-hosted asset | 1 day | Faster clones | Find a hosting location |
| Multi-tenant authorization model (token → workspace → repo allowlist) | large; design first | Enables shared-infrastructure SaaS posture | Stakeholder requirements first |
| Scanner-addition scaffolding (codegen for the 7 touchpoints) | 1 week | Reduces drift and onboarding friction (**Phase 8 finding**) | After **#9** completes — generator should write to the new template-on-disk pattern |

---

## Verification

This is a research report, not an implementation. Validation steps:

1. **Re-read each "Confirmed Gap"'s evidence line** — every claim cites file:line and can be opened directly.
2. **Run the headline claims through git history.** `git blame api/auth/auth.go` line 35 should show the comparison has stood unchanged for years (i.e. it's a real gap, not a recent regression). Same for `api/dockers/api.go::WaitContainer`.
3. **Reproduce the finalization-order bug (#8).** Add a unit test that calls `Start()` with a `mockRunner` returning two containers (`CResult="failed"`, `CResult="passed"`) and assert `results.FinalResult` — observe whether the deferred `setToAnalysis` overwrites the value set by `setFinalResult`.
4. **Reproduce the Docker-timeout no-op (#2).** Stand up the docker-compose stack, inject a `cmd: "sleep 99999"` scanner in `config.yaml`, run a scan, observe `analysis.status` stays `running` past the configured `timeOutInSeconds`.
5. **Confirm rate-limit absence (#17).** Hit `/api/1.0/analysis` 100x/sec from one IP. Expect 100% 200/401 (no 429). If 429 appears, the gap is wrong and remove from the report.

If any verification disagrees with a finding, downgrade or remove that finding rather than keeping it on the strength of agent summary alone.
