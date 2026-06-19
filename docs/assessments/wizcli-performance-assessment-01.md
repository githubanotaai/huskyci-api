# HuskyCI - WizCLI Performance Assessment

## Summary

The three requested line anchors map to `wizcli_iac`, `wizcli_sast`, and `wizcli_vulns`; all three use `939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz:f793155-amd64`, are `type: Generic`, `default: true`, `timeOutInSeconds: 600`, and run `wizcli scan dir ./code` against the repository root with different `--disabled-scanners` sets. The repo also contains a default `wizcli_secrets` entry with the same execution profile; per scope, this assessment focuses on the three requested variants and notes where the fourth would worsen multipliers.

WizCLI differs from gosec/bandit because the dominant variable is not local CPU or filesystem traversal; it is `wizcli auth` plus cloud scan/upload/result retrieval inside each container. That network-dependent work is wrapped by HuskyCI as if it were a local scanner command.

The highest-impact improvement without architectural change is to add config-level changed-file preflight guards before `wizcli auth`, so README-only or unrelated PRs emit an empty valid result without paying auth/upload/scan cost. Add command-level timeout wrappers around `wizcli auth` and `wizcli scan` at the same time.

## Confirmed findings

### Three default Generic WizCLI variants scan the same root independently

**Severity:** High

**Evidence:** `wizcli_iac`, `wizcli_sast`, and `wizcli_vulns` all run `wizcli scan dir ./code` in `api/config.yaml:675`, `api/config.yaml:774`, and `api/config.yaml:812`. All are `type: Generic`, `default: true`, `timeOutInSeconds: 600` at `api/config.yaml:717`, `api/config.yaml:791`, and `api/config.yaml:828`.

**Cross-reference:** Gap #3 plus wizcli-specific duplication

**Impact:** They enter the same `runGenericScans` errgroup and start without internal sequencing, so auth + repository clone/upload + scan setup are paid three times in parallel. `wizcli_secrets` at `api/config.yaml:573` would make this four default WizCLI containers in production.

**Recommendation:** Collapse duplicate root traversal where possible, or add pre-auth changed-file guards in each WizCLI `cmd`.

**Verifiable by:** Static analysis

### Each variant authenticates separately

**Severity:** High

**Evidence:** The three scoped entries each run `wizcli auth --id '%WIZ_CLIENT_ID%' --secret '%WIZ_CLIENT_SECRET%'` before scanning: `api/config.yaml:670`, `api/config.yaml:744`, `api/config.yaml:807`.

**Cross-reference:** wizcli-specific

**Impact:** A scan that triggers all three scoped variants implies at least `3x` auth round-trip cost versus `1x` if one WizCLI container authenticated once and ran the enabled scan modes. The exact Wiz API request count per auth cannot be verified statically.

**Recommendation:** Short term: skip auth when changed files are irrelevant. Long term: one WizCLI orchestration container or shared token cache.

**Verifiable by:** Static analysis for separate auth commands; benchmark or WizCLI docs for exact round-trip count

### Docker mode does not enforce the configured 600-second WizCLI timeout

**Severity:** Critical

**Evidence:** `timeOutInSeconds: 600` is configured for all three scoped variants, but Docker `WaitContainer(timeOutInSeconds int)` never uses the parameter and waits on `ContainerWait(context.Background(), ...)`: `api/dockers/api.go:100`. K8s does enforce `TimeoutSeconds` and removes the pod on timeout at `api/kubernetes/api.go:198`.

**Cross-reference:** Bug #2

**Impact:** In Docker mode, a Wiz auth or cloud scan hang can hold the scanner goroutine indefinitely and delay final analysis persistence. Language scanners are started concurrently by the top-level errgroup at `api/securitytest/run.go:67`, but final completion still waits.

**Recommendation:** Fix Docker `WaitContainer` with `context.WithTimeout`, stop/remove timed-out containers, and preserve scanner error output.

**Verifiable by:** Static analysis; Docker-mode timeout test

### Delta scanning does not suppress WizCLI execution

**Severity:** High

**Evidence:** Generic scanners are selected by `{"type": "Generic", "default": true}` without language or changed-file filtering at `api/securitytest/run.go:279`. `ChangedFiles` is passed into the command template, but `runGenericScans` still launches each default generic scanner at `api/securitytest/run.go:94`. `wizcli_vulns` has no `HUSKYCI_DELTA_SCAN` sparse-checkout branch at `api/config.yaml:805`.

**Cross-reference:** wizcli-specific

**Impact:** A PR that changes only README or unrelated source still launches all default WizCLI variants unless disabled by env/config; for WizCLI that means avoidable network auth and cloud scan work, not just local CPU.

**Recommendation:** Add config-level skip guards before auth, and near-term move scanner selection into `run.go` using `changedFiles` and scanner scope metadata.

**Verifiable by:** Static analysis

### WizCLI output is fully buffered and parsed after unbounded log reads

**Severity:** Critical

**Evidence:** Docker reads logs with `io.ReadAll` at `api/dockers/api.go:197`; K8s does the same at `api/kubernetes/api.go:247`. Wiz parsing then calls `json.Unmarshal([]byte(output), &report)` at `api/securitytest/wizcli.go:379`. The 1 MB truncation happens only later in `prepareContainerAfterScan` at `api/securitytest/securitytest.go:180`.

**Cross-reference:** Probable `io.ReadAll` gap

**Impact:** Cloud-enriched Wiz output is read fully into memory, converted to string, then copied again for JSON parsing. With three scoped variants in parallel, worst-case buffer pressure is multiplied.

**Recommendation:** Add bounded log readers before `COutput`, then stream or size-limit Wiz JSON parsing.

**Verifiable by:** Static analysis; large-output benchmark

### Wiz image is tag-pinned, not digest-pinned

**Severity:** Medium

**Evidence:** Each scoped variant uses `imageTag: "f793155-amd64"` rather than an `@sha256:` digest: `api/config.yaml:650`, `api/config.yaml:724`, `api/config.yaml:798`. Docker/K8s image construction appends `image:tag`, not digest form, at `api/dockers/huskydocker.go:23`.

**Cross-reference:** Gap #6

**Impact:** Static analysis cannot prove registry tag immutability. If the tag is overwritten, WizCLI binary behavior and performance can change without config diffs.

**Recommendation:** Support digest image references or enforce immutable registry tags and record `extraInfo.clientVersion` in scan metadata.

**Verifiable by:** Static analysis plus registry policy check

## Probable findings

### Wiz API outage behavior is not characterized

**Severity estimate:** Critical

**Indicators:** Commands rely on WizCLI's own behavior for `auth` and `scan`; Docker mode has no external timeout. `analyzeWizCLI` recognizes only `ERROR_AUTH_WIZCLI` and `ERROR_RUNNING_WIZCLI_SCAN` at `api/securitytest/wizcli.go:128`.

**Cannot verify because:** Static analysis does not show whether WizCLI retries, exits quickly, or hangs on unreachable Wiz APIs.

**Investigation:** Run Docker and K8s scans with Wiz API egress blocked; record wall-clock, stdout/stderr, exit codes, and whether sentinels are emitted.

### Timeout value is not demonstrably calibrated for cloud latency

**Severity estimate:** Medium

**Indicators:** All scoped variants use the same flat `600` seconds with no stage budget for auth, upload, scan processing, or result retrieval.

**Cannot verify because:** Requires measured WizCLI latency distributions and/or WizCLI retry documentation.

**Investigation:** Add per-stage timing around auth and scan in a test image or wrapper, then set timeout from observed percentiles and failure-mode policy.

### Server-side deduplication cannot be assumed

**Severity estimate:** Medium

**Indicators:** HuskyCI runs independent containers with independent auth and independent `/tmp/wizResult.json` files.

**Cannot verify because:** Whether Wiz SaaS deduplicates uploads/results across independent CLI invocations requires Wiz documentation or measurement.

**Investigation:** Run the three modes on the same repo with correlation IDs and inspect Wiz-side scan records.

## Strengths

- The integration uses a shared parser for all WizCLI variants via `securityTestAnalyze` mapping at `api/securitytest/securitytest.go:32`.
- Parser coverage is broad: libraries, OS packages, secrets, data findings, IaC, SAST, malware, AI models, and software supply chain are modeled in `api/securitytest/wizcli.go:18`.
- Existing tests cover empty JSON, invalid JSON, no findings, auth failure, scan failure, and several result categories in `api/securitytest/wizcli_test.go:35`.
- K8s mode has a real runtime timeout and deletes timed-out pods at `api/kubernetes/api.go:225`.
- Wiz commands write JSON to `/tmp/wizResult.json` and suppress normal scan stdout, reducing noisy container logs.

## Prioritized improvements

### Immediate (0-30 days)

- Add changed-file pre-auth guards in the three WizCLI `cmd` templates. Effort: M. Impact: High. Addresses duplicate execution and delta waste.
- Add command-level auth/scan timeout sentinels in `config.yaml`. Effort: S-M. Impact: High in Docker mode. Addresses outage behavior until Bug #2 is fixed.
- Add `wizcli.go` input-size guard before `json.Unmarshal` and tests for large output, auth failure, timeout text, and real IaC/SAST fixtures. Effort: S. Impact: Medium. Addresses parser and memory test gaps.

### Near-term (30-90 days)

- Fix Docker timeout enforcement and cleanup in `api/dockers/api.go`. Effort: M. Impact: Critical. Addresses Bug #2 for WizCLI.
- Add bounded log reading for Docker and K8s before storing `COutput`. Effort: M. Impact: Critical. Addresses unbounded output amplification.
- Add scanner selection logic in `run.go` so Generic cloud scanners can skip based on changed files and scanner scope. Effort: M-L. Impact: High.

### Long-term (90+ days)

- Replace separate WizCLI variant containers with one WizCLI orchestration container that authenticates once and runs required modes. Effort: L. Impact: High.
- Stream Wiz results into parser/storage with size limits and per-stage timing. Effort: L. Impact: Critical.
- Add cloud-scanner telemetry: auth duration, scan duration, output bytes, timeout reason, and WizCLI version. Effort: M-L. Impact: High.
