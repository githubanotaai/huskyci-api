# HuskyCI API -- Performance Gap Assessment

## Executive Summary

Throughput posture: HuskyCI API accepts scans asynchronously, but it does not control the amount of work admitted after acceptance. `POST /analysis` returns quickly after validation and MongoDB preflight checks, then starts `analysis.StartAnalysis` in a detached goroutine (`api/routes/analysis.go:84-162`). Once accepted, each scan can fan out into one enry container plus generic and language scanner containers with no global semaphore, no queue, and no rejection policy. The real throughput ceiling is therefore not the HTTP server; it is the combined saturation point of Docker/Kubernetes, MongoDB collection scans, process memory, and Go scheduler overhead under unbounded goroutine growth.

Latency posture: request acceptance latency is bounded by JSON binding, token validation, input regex checks, and unindexed MongoDB preflight reads. End-to-end scan completion latency is dominated by scanner container lifecycle and log/result processing. In Kubernetes mode, scheduling and scanner execution have explicit watch timeouts. In Docker mode, prior finding #2 means scanner execution has no effective deadline after container start; a stuck scanner can keep the analysis in `running` indefinitely. The largest configured scanner deadline is `spotbugs.timeOutInSeconds: 3600` in `api/config.yaml:397-451`, and in Docker mode even that upper bound is not enforced.

Top 5 performance risks ranked by severity x likelihood:

1. **Critical -- unbounded scan admission plus unbounded scanner fan-out:** `ReceiveRequest` spawns `StartAnalysis` with no queue (`api/routes/analysis.go:160`), and `RunAllInfo.Start` fans scanners out via unbounded errgroups (`api/securitytest/run.go:67-184`). Cross-reference: prior finding #3.
2. **Critical -- unbounded scanner stdout/log buffering:** Docker and Kubernetes both read full scanner logs with `io.ReadAll` and no pre-read byte cap (`api/dockers/api.go:188-203`, `api/kubernetes/api.go:233-257`).
3. **Critical -- Docker scanner timeout is ineffective:** Docker `WaitContainer` receives `timeOutInSeconds` but uses `context.Background()` and never applies the timeout (`api/dockers/api.go:99-116`). Cross-reference: prior finding #2.
4. **High -- MongoDB hot-path queries are unindexed and grow linearly:** request dedupe, result polling, scanner metadata reads, and final analysis update all use query shapes with no declared indexes (`api/db/huskydb.go:37-72, 110-130, 249-279`; prior finding #11).
5. **High -- no graceful shutdown or resource drain:** detached scans are not coordinated with process shutdown (`api/server.go:23-110`; prior finding #4), so restarts can leave containers/pods and `running` rows behind, increasing later scan and polling load.

Observability readiness: performance cannot be measured today from the running service because there is no `/metrics`, no traces, no latency fields, no queue depth, and no propagated request/scan correlation beyond ad hoc RID logging.

## Confirmed Performance Gaps

### Accepted Scans Bypass Backpressure
**Severity:** Critical
**Phase:** 1, 2, 4
**Evidence:** `api/routes/analysis.go:84-162`, specifically `go analysis.StartAnalysis(RID, repository)` at line 160.
**Impact:** The HTTP handler returns `201 Created` after local validation and MongoDB preflight, before any scanner container is running. If scan requests arrive faster than Docker/Kubernetes can start containers, the API still accepts more work and accumulates detached goroutines. This is structural overload amplification: admission is O(requests), while work created is O(requests x scanners).
**Cross-reference:** Prior finding #3.
**Recommendation:** Replace direct goroutine spawn with a bounded work queue or global scan semaphore. Return `429 Too Many Requests` or `503 Service Unavailable` when the queue is full. Track queue depth and in-flight scans.
**Benchmark needed:** `BenchmarkScanGoroutineFanout`.

### Enry Is Synchronous Inside The Detached Scan Worker
**Severity:** Medium
**Phase:** 1
**Evidence:** `api/analysis/analysis.go:20-95`; `enryScan.Start()` runs at lines 84-87 before `allScansResults.Start(enryScan)` at lines 90-93.
**Impact:** Enry does not block the HTTP response, but it serializes the background critical path: no generic or language scanners start until enry finishes and language detection is parsed. Minimum scan completion latency is therefore at least the enry container lifecycle plus final Mongo update, even when every later scanner is instant.
**Cross-reference:** New finding.
**Recommendation:** Keep enry synchronous because later language scanner selection depends on it, but instrument `enry` separately and enforce the same timeout semantics in both Docker and Kubernetes modes.
**Benchmark needed:** None -- statically verifiable.

### Generic And Language Scanner Groups Run Concurrently, Not Sequentially
**Severity:** Low
**Phase:** 1
**Evidence:** `api/securitytest/run.go:67-76` starts `runGenericScans` and `runLanguageScans` as two goroutines under one top-level errgroup. Nested waits occur inside `runGenericScans` (`api/securitytest/run.go:85-128`) and `runLanguageScans` (`api/securitytest/run.go:130-184`).
**Impact:** Current source does not have two sequential top-level `Wait()` calls. A slow generic scanner does not prevent language scanners from starting after both wrapper goroutines are scheduled. The critical path is `enry duration + max(generic group duration, language group duration) + final Mongo update`, with runtime-container overhead and Mongo query latency inside each group.
**Cross-reference:** New finding.
**Recommendation:** Preserve concurrent group startup, but add `errgroup.SetLimit` or a weighted semaphore inside each group to cap scanner fan-out.
**Benchmark needed:** `BenchmarkErrgroupFanout`.

### Per-Scan Goroutine Fan-Out Has No Limit
**Severity:** Critical
**Phase:** 2
**Evidence:** `api/securitytest/run.go:67-184`; each `g.Go` call is unconditional for enabled scanner tests, and no `SetLimit` or semaphore is used.
**Impact:** Minimum spawned goroutines per accepted request is one detached `StartAnalysis` goroutine when enry fails before `RunAllInfo.Start`. If enry succeeds but no later tests exist, `RunAllInfo.Start` adds two wrapper goroutines. With all registered post-enry scanners active, current code can spawn `1 + 2 + 16 = 19` request-owned goroutines: one `StartAnalysis`, two group wrappers, six generic scanner goroutines, and ten language scanner goroutines including `spotbugs`. At N concurrent scans, this is:

| Concurrent scans | Minimum, enry fails | Empty post-enry groups | All scanners active |
|---:|---:|---:|---:|
| 10 | 10 | 30 | 190 |
| 100 | 100 | 300 | 1,900 |
| 1,000 | 1,000 | 3,000 | 19,000 |

Go goroutines are multiplexed over OS threads, so thousands of goroutines are expected to work structurally, but the point where scheduler overhead becomes measurable depends on blocking profile, stack growth, memory retention, and runnable goroutine count. Unable to verify from static analysis — requires benchmark: `BenchmarkScanGoroutineFanout` (specified in Phase 6).
**Cross-reference:** Prior finding #3.
**Recommendation:** Use a global semaphore for total active scanner containers and per-analysis limits for intra-analysis concurrency. Export `runtime.NumGoroutine` and scanner queue depth.
**Benchmark needed:** `BenchmarkScanGoroutineFanout`, `BenchmarkErrgroupFanout`.

### Docker Scanner Deadline Budget Is Not Enforced
**Severity:** Critical
**Phase:** 1, 4
**Evidence:** `api/dockers/api.go:99-116`; `WaitContainer(timeOutInSeconds int)` ignores the argument and waits with `context.Background()`.
**Impact:** In Docker mode, the configured scanner timeout is not a maximum latency bound. A hung container keeps its scanner goroutine, Docker resources, and parent analysis goroutine alive indefinitely. `spotbugs` is configured with `timeOutInSeconds: 3600` (`api/config.yaml:397-451`), but prior finding #2 means Docker mode can exceed that bound without returning.
**Cross-reference:** Prior finding #2.
**Recommendation:** Use `context.WithTimeout` in `WaitContainer`, stop/remove the container on timeout, and propagate timeout errors into `RunAllInfo.SetAnalysisError`.
**Benchmark needed:** None -- statically verifiable.

### Docker Image Pull Latency Is Outside Scanner Runtime Timeout
**Severity:** High
**Phase:** 1
**Evidence:** `api/dockers/huskydocker.go:37-87`; image load/pull happens at lines 45-51 before `CreateContainer`, `StartContainer`, and `WaitContainer`. Pull retry timeout is independent: `time.After(15 * time.Minute)` at `api/dockers/huskydocker.go:89-109`.
**Impact:** Docker image pull can add up to its own 15-minute budget before scanner execution begins. This budget is not the scanner's `timeOutInSeconds`, and in Docker mode scanner execution itself is unbounded because of prior finding #2. Image pull is cached at the daemon level via `ImageIsLoaded` (`api/dockers/api.go:232-246`), but cold hosts or tag drift can create a latency cliff per scanner image.
**Cross-reference:** New finding.
**Recommendation:** Pre-pull scanner images at startup or deployment, close/read image-pull streams correctly, expose image-pull latency metrics, and include image availability in readiness checks.
**Benchmark needed:** None -- static control flow is verifiable; live pull latency requires deployment measurement.

### Docker Client Is Created Per Scanner
**Severity:** High
**Phase:** 2
**Evidence:** `api/dockers/huskydocker.go:37-43` calls `NewDocker` for every scanner; `api/dockers/api.go:39-75` creates a new Docker SDK client from environment variables.
**Impact:** The API does not share a Docker client across concurrent scanners. Each scanner rebuilds client state and mutates process-wide Docker environment variables (`DOCKER_HOST`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`) at `api/dockers/api.go:46-66`. Whether HTTP connections pool across clients is not visible from this code, but this pattern prevents HuskyCI from imposing a central Docker request budget and increases pressure on the Docker daemon under scan bursts. Simultaneous `ContainerCreate` and `ContainerStart` calls eventually serialize or queue at the Docker daemon, but the API keeps producing goroutines first.
**Cross-reference:** Prior finding #3.
**Recommendation:** Build one Docker client per configured Docker host during startup, keep it immutable, and gate Docker operations through a per-host semaphore.
**Benchmark needed:** `BenchmarkScanGoroutineFanout`.

### Kubernetes Clientset Is Created Per Scanner With Default Client Rate Limits
**Severity:** High
**Phase:** 2
**Evidence:** `api/kubernetes/huskykube.go:49-56` calls `NewKubernetes` per scanner; `api/kubernetes/api.go:36-65` builds a new config and `kube.NewForConfig(config)`. No custom `QPS` or `Burst` fields are set in the config.
**Impact:** The client-go defaults are `DefaultQPS = 5.0` and `DefaultBurst = 10`, but this code creates a separate clientset per scanner rather than sharing one process-wide limiter. That can multiply API server pressure across concurrent scans while still leaving individual scanner goroutines waiting on client-side or API-server throttling. Pod scheduling latency is counted by `podSchedulingTimeoutInSeconds` until the pod reaches `Running`; scanner execution is then counted by `testTimeOutInSeconds` (`api/kubernetes/api.go:152-230`).
**Cross-reference:** Prior finding #3.
**Recommendation:** Build a shared Kubernetes clientset at startup, configure explicit `QPS`/`Burst` from environment, and add a global pod-create semaphore.
**Benchmark needed:** `BenchmarkScanGoroutineFanout` for local fan-out; live API throttling requires cluster instrumentation.

### Kubernetes WaitPod Has A Deadline Budget, But Log Collection Does Not
**Severity:** High
**Phase:** 1
**Evidence:** `api/kubernetes/api.go:152-230` uses `metav1.ListOptions.TimeoutSeconds` for scheduling and running watches; `api/kubernetes/api.go:233-257` reads logs with `io.ReadAll`.
**Impact:** Kubernetes mode bounds the wait for `Running` and terminal pod state, including image pull and scheduling while the pod is Pending. After the pod finishes, log retrieval remains unbounded by bytes read and can allocate until the API process runs out of memory.
**Cross-reference:** New finding.
**Recommendation:** Wrap pod log streams with `io.LimitReader`, emit output byte metrics, and fail scans that exceed a configured output limit.
**Benchmark needed:** `BenchmarkReadOutputBuffering`.

### Scanner Output Is Read Fully Into Memory Before Any Cap Applies
**Severity:** Critical
**Phase:** 1, 3
**Evidence:** Docker `ReadOutput` uses `io.ReadAll(out)` and `string(body)` at `api/dockers/api.go:188-203`; Kubernetes does the same at `api/kubernetes/api.go:233-257`. The only output cap is post-read and post-parse: `cOutputMaxSize := 1000000` in `api/securitytest/securitytest.go:178-189`.
**Impact:** There is no size bound on the log stream before allocation. `io.ReadAll` grows a byte slice for the full output, `string(body)` copies it, and most analyzers convert the string back to `[]byte` for JSON/XML parsing. A scanner that emits 100MB can transiently require multiple copies before the eventual stored `COutput` truncation. Spotbugs XML and dependency scanners can produce large outputs on large repositories.
**Cross-reference:** New finding.
**Recommendation:** Replace `io.ReadAll` with bounded reads (`io.LimitReader` or streaming decoder), return a typed "output too large" scan error when exceeded, and record the byte count before truncation.
**Benchmark needed:** `BenchmarkReadOutputBuffering`.

### Parse Error Path Can Retain Full Scanner Output In Error Strings
**Severity:** High
**Phase:** 3
**Evidence:** `api/util/util.go:141-143` builds `fmt.Errorf("%s\nError from top: %v", containerOutput, otherErr)`. Parser call sites pass full `Container.COutput`, for example `api/securitytest/gosec.go:52-56`, `api/securitytest/bandit.go:39-41`, and `api/securitytest/spotbugs.go:110-115`.
**Impact:** Even though `prepareContainerAfterScan` later truncates `Container.COutput`, parse failures can retain the complete raw output inside `scanInfo.ErrorFound`. `registerFinishedAnalysis` converts that error to a string for MongoDB at `api/analysis/analysis.go:116-135`, creating another large allocation and possibly a large `errorFound` field.
**Cross-reference:** New finding.
**Recommendation:** Change `HandleScanError` to include a bounded prefix/suffix and byte count, not the complete scanner output.
**Benchmark needed:** `BenchmarkReadOutputBuffering`.

### MongoDB Request-Acceptance Reads Are Unindexed
**Severity:** High
**Phase:** 2, 4
**Evidence:** `ReceiveRequest` calls `FindOneDBRepository` with `{"repositoryURL": repository.URL}` (`api/routes/analysis.go:116-124`) and `FindOneDBAnalysis` with `{"repositoryURL": repository.URL, "repositoryBranch": repository.Branch}` (`api/routes/analysis.go:136-155`). Query builders are in `api/db/huskydb.go:37-72`. No indexes are declared in `api/db/mongo/mongo.go`.
**Impact:** With prior finding #11, these preflight reads can become collection scans. MongoDB collection scans compare each document to the query predicate when no suitable index covers the query, so latency grows linearly with collection size. At 1k, 10k, and 100k documents, the expected growth function is O(N), not O(1); exact latency in milliseconds depends on data size, storage, cache state, and deployment. Unable to verify from static analysis — requires benchmark: `BenchmarkMongoAnalysisQueries` (specified in Phase 6).
**Cross-reference:** Prior finding #11.
**Recommendation:** Add indexes on `repository.repositoryURL`, `analysis.RID`, and compound `analysis.repositoryURL + analysis.repositoryBranch + analysis.status`. Query running analyses with `status:"running"` and use a deterministic sort or unique active-scan guard.
**Benchmark needed:** `BenchmarkMongoAnalysisQueries`.

### In-Flight Deduplication Is Not Effective Throttling
**Severity:** High
**Phase:** 2
**Evidence:** Deduplication is a single `FindOneDBAnalysis` on URL and branch at `api/routes/analysis.go:136-155`; it only rejects if the returned document has `Status == "running"`.
**Impact:** This is not a capacity control. It only targets duplicate URL+branch submissions and does not limit distinct repositories, distinct branches, or scanner fan-out. Because the query is not scoped to `status:"running"` and has no sort, completed analyses can interfere with the intended check, reducing any throttle effect under accumulated history.
**Cross-reference:** Prior finding #11 for index absence; new performance consequence.
**Recommendation:** Add a true global admission controller and replace dedupe with an indexed active-scan table or compound unique index for `(repositoryURL, repositoryBranch, status=running)`.
**Benchmark needed:** `BenchmarkMongoAnalysisQueries`.

### MongoDB Scanner Metadata Reads Multiply With Scanner Count
**Severity:** Medium
**Phase:** 2
**Evidence:** `getAllDefaultSecurityTests` calls `FindAllDBSecurityTest` (`api/securitytest/run.go:279-293`). `runGenericScans` calls it once for `type:"Generic"` (`api/securitytest/run.go:85-92`); `runLanguageScans` calls it once per detected language (`api/securitytest/run.go:134-141`). Every scanner then calls `FindOneDBSecurityTest` in `SecTestScanInfo.New` (`api/securitytest/securitytest.go:69-91`).
**Impact:** Even if the `securityTest` collection is small, scanner metadata reads are in the active scan hot path. At maximum scanner fan-out, the API repeats metadata lookups that could be immutable in memory. With prior finding #11, these are also unindexed collection scans if no default `_id` lookup is used.
**Cross-reference:** Prior finding #11.
**Recommendation:** Load scanner metadata into an immutable in-memory map at startup, refresh explicitly on admin changes, and remove per-scanner `FindOneDBSecurityTest` calls.
**Benchmark needed:** `BenchmarkMongoAnalysisQueries`.

### Final Analysis Update Can Hit MongoDB BSON Size Limit
**Severity:** High
**Phase:** 3
**Evidence:** `registerFinishedAnalysis` writes `containers`, `huskyciresults`, `codes`, and `errorFound` into one analysis document (`api/analysis/analysis.go:116-135`). Types embed nested arrays in `api/types/types.go:32-160`.
**Impact:** Analysis document growth is bounded only by MongoDB's 16 MiB BSON document limit, not by HuskyCI field-level limits. Large `Codes[]`, many `Containers[]`, and high vulnerability counts can make BSON encoding slow or fail the final update. The raw `io.ReadAll` output, parsed result structs, vulnerability arrays, and BSON encoding buffers can coexist briefly, creating double or triple allocation risk.
**Cross-reference:** Prior finding #11.
**Recommendation:** Store scanner outputs/findings in separate documents keyed by RID and scanner name, keep the analysis document as an indexable summary, and cap per-scan finding counts.
**Benchmark needed:** `BenchmarkAnalysisBSONEncodingWorstCase`.

### Polling Amplifies MongoDB Reads
**Severity:** High
**Phase:** 4
**Evidence:** `GetAnalysis` queries by `RID` at `api/routes/analysis.go:44-80`; query builder is `FindOneDBAnalysis` at `api/db/huskydb.go:61-72`. No index on `RID` is declared in `api/db/mongo/mongo.go`.
**Impact:** The client polling contract creates read load as:

```text
reads_per_second = concurrent_scans * (1 / poll_interval_seconds)
```

Polling becomes the dominant MongoDB read workload when `concurrent_scans / poll_interval_seconds` exceeds the active scan hot-path read rate. The exact crossing point cannot be derived statically because the repository does not enforce poll interval, scan duration distribution, or client retry limits. Because `RID` is not declared indexed, each poll can degrade from O(1) expected lookup to O(N) collection scan under prior finding #11.
**Cross-reference:** Prior finding #11.
**Recommendation:** Add a unique index on `analysis.RID`, enforce server-side polling rate limits, return `Retry-After`, and consider long polling or callback/webhook completion.
**Benchmark needed:** `BenchmarkMongoAnalysisQueries`.

### MongoDB Operations Use Contexts Without Deadlines
**Severity:** Medium
**Phase:** 4
**Evidence:** MongoDB wrapper methods use `context.TODO()` for `InsertOne`, `UpdateOne`, `Find`, `FindOne`, `FindOneAndUpdate`, and cursor reads (`api/db/mongo/mongo.go:96-174`).
**Impact:** Slow server selection, reconnect, collection scans, or network stalls are not bounded per operation in code. During reconnect, `autoReconnect` pings every second and calls `Disconnect`/`Connect` on the shared client (`api/db/mongo/mongo.go:76-94`). Whether in-flight queries queue, block, or fail depends on driver behavior and deployment state. Unable to verify from static analysis — requires benchmark: `BenchmarkMongoReconnectDuringScan` (specified in Phase 6).
**Cross-reference:** Prior finding #11.
**Recommendation:** Add per-operation contexts with deadlines and expose Mongo operation duration/error metrics.
**Benchmark needed:** `BenchmarkMongoReconnectDuringScan`.

### No Graceful Shutdown Drains In-Flight Work
**Severity:** Critical
**Phase:** 4
**Evidence:** `api/server.go:23-110` starts Echo with `Start`/`StartTLS` and no signal handler, no `Shutdown`, and no in-flight analysis `WaitGroup`.
**Impact:** On deploy/restart, detached analysis goroutines can terminate without finalizing Mongo rows or removing containers/pods. The next process starts with stale `running` rows, orphaned runtime resources, and clients polling old RIDs. Under repeated deploys or crashes, this increases background load and reduces available container capacity.
**Cross-reference:** Prior finding #4.
**Recommendation:** Add graceful shutdown with a bounded context, track active analyses, stop/remove active containers or pods, and run a stale-analysis reaper on startup.
**Benchmark needed:** None -- statically verifiable; cleanup effectiveness needs integration testing.

### CheckMaliciousRepoURL Recompiles Regex Per Request
**Severity:** Low
**Phase:** 6
**Evidence:** `api/util/util.go:168-181` calls both `regexp.MustCompile(regexpGit)` and `regexp.MatchString(regexpGit, repositoryURL)` on every request.
**Impact:** Regex compilation and duplicate matching add avoidable CPU allocation in the request-acceptance path. This is not the dominant cost compared with MongoDB and container runtime, but it is measurable under high rejected/accepted request rates.
**Cross-reference:** New finding.
**Recommendation:** Hoist the compiled regex to a package-level `var` and call `FindString`/`MatchString` once.
**Benchmark needed:** `BenchmarkCheckMaliciousRepoURLConcurrent`.

### Performance Instrumentation Is Absent
**Severity:** High
**Phase:** 5
**Evidence:** No Prometheus/OpenTelemetry references in `api/go.mod:1-23`; only request ID middleware exists at `api/server.go:54-57`; logger wrapper accepts positional variadic messages with fixed `action` and `info` fields (`api/log/log.go:29-57`).
**Impact:** The platform cannot answer core performance questions: request rate, scan concurrency, scanner duration, runtime saturation, output size, MongoDB latency, Docker/Kubernetes error rates, or goroutine count. Without those signals, tuning is guesswork and saturation is discovered after user-visible failures.
**Cross-reference:** New finding.
**Recommendation:** Add `github.com/prometheus/client_golang/prometheus` and `github.com/prometheus/client_golang/prometheus/promhttp`, expose `/metrics`, and instrument the exact locations listed in Phase 5 below.
**Benchmark needed:** None for absence; metric usefulness validated operationally.

## Probable Performance Gaps

### Docker Daemon Serialization Under Container Bursts
**Severity estimate:** High
**Indicators:** Every scanner calls `ContainerCreate` (`api/dockers/api.go:77-91`) and `ContainerStart` (`api/dockers/api.go:93-97`) through per-scanner clients, with no HuskyCI-side semaphore.
**Unable to verify because:** Docker daemon scheduling, image layer locks, HTTP connection behavior, and host capacity are external runtime properties.
**Benchmark spec:**

```text
Benchmark name: BenchmarkDockerContainerStartBurst
File: api/dockers/api_bench_test.go
What it measures: ContainerCreate + ContainerStart latency under increasing parallel scanner starts.
Setup: Local Docker daemon with scanner image pre-pulled and a no-op command image.
Input range: Parallelism 1, 5, 10, 20, 50.
Expected result: P95 start latency grows sublinearly until the configured daemon capacity.
Regression threshold: Flag if P95 grows superlinearly or Docker errors appear before the intended global limit.
Gap analysis reference: probable Docker runtime ceiling, prior finding #3.
```

### Kubernetes API Server Throttling Under Pod Bursts
**Severity estimate:** High
**Indicators:** `NewKubernetes` creates a clientset per scanner (`api/kubernetes/api.go:36-65`), and no explicit `QPS`/`Burst` is configured.
**Unable to verify because:** API server throttling depends on cluster version, client config, admission controllers, and control-plane load.
**Benchmark spec:**

```text
Benchmark name: BenchmarkKubernetesPodCreateBurst
File: api/kubernetes/api_bench_test.go
What it measures: Pod create + watch setup latency and client/server throttle errors under burst fan-out.
Setup: Test namespace, shared no-op scanner image, cleanup hook for created pods.
Input range: Parallel pod creates 1, 5, 10, 20, 50.
Expected result: Latency and 429/throttle events stay within the configured client/server QPS budget.
Regression threshold: Flag if pod creation P99 exceeds podSchedulingTimeout / 2 or any throttling appears below intended capacity.
Gap analysis reference: probable Kubernetes runtime ceiling, prior finding #3.
```

### MongoDB Reconnect Effects On Active Scans
**Severity estimate:** Medium
**Indicators:** `autoReconnect` calls `Disconnect` and `Connect` on the shared client while all query methods use `context.TODO()` (`api/db/mongo/mongo.go:76-174`).
**Unable to verify because:** In-flight behavior depends on MongoDB driver internals, server selection timeout, deployment topology, and timing of disconnect relative to operations.
**Benchmark spec:**

```text
Benchmark name: BenchmarkMongoReconnectDuringScan
File: api/db/mongo/mongo_bench_test.go
What it measures: Query/update latency and error rate while the reconnect loop runs during active analysis operations.
Setup: Test MongoDB instance, seeded analysis/securityTest collections, controlled network interruption or mock server.
Input range: Concurrent scan DB operation counts 1, 10, 50 with reconnect intervals.
Expected result: Operations either fail quickly with bounded errors or recover within configured deadlines.
Regression threshold: Flag if any operation blocks beyond the configured DB timeout or goroutines leak.
Gap analysis reference: probable reconnect latency gap, prior finding #11.
```

## Phase 1 -- Execution Path Latency Analysis

### 1a. Request Acceptance Latency

`ReceiveRequest` is asynchronous with respect to scan execution. The handler performs JSON binding, token authorization, input checks, repository lookup/insert, and active-analysis dedupe. It then starts `analysis.StartAnalysis` as a goroutine at `api/routes/analysis.go:160` and returns `201 Created` at `api/routes/analysis.go:161-162`.

Minimum request acceptance latency is the local validation path plus MongoDB preflight calls. Maximum request acceptance latency is unbounded by code because MongoDB calls use `context.TODO()` in `api/db/mongo/mongo.go:96-174` and preflight queries have no indexes under prior finding #11. The HTTP client does not block for the full scan duration unless MongoDB preflight itself stalls.

| Stage | Sync/async boundary | Minimum latency | Maximum latency in current code | Deadline budget consumed |
|---|---|---|---|---|
| `ReceiveRequest` validation and preflight | Synchronous before HTTP response | JSON bind + token auth + regex validation + Mongo preflight | Unbounded by code because Mongo operations have no per-call context deadline | MongoDB preflight dominates if collections grow |
| `StartAnalysis` registration and enry | Asynchronous after line 160 | Insert running analysis + instant enry container/log parse | Docker mode unbounded if enry hangs; Kubernetes bounded by scheduling timeout + enry timeout + log read | Enry is mandatory and serial before other scanners |
| Generic/language scanner fan-out | Asynchronous background errgroup | Instant scanner metadata reads + instant containers + instant parse | Docker mode unbounded per scanner; Kubernetes bounded by per-pod waits plus unbounded log byte reads | Slowest scanner group dominates |
| Finalization | Background defer in `StartAnalysis` | Single Mongo update | Unbounded by code because Mongo update has no operation deadline and BSON can grow | Final Mongo update dominates for large documents |

### 1b. errgroup Coordination Cost

Current source uses one top-level errgroup, not two sequential top-level waits. `RunAllInfo.Start` launches `runGenericScans` and `runLanguageScans` concurrently at `api/securitytest/run.go:67-74`, then waits once at `api/securitytest/run.go:76`.

Each group has its own nested errgroup. The critical path is:

```text
enry container lifecycle
+ max(generic scanner group duration, language scanner group duration)
+ result aggregation/final Mongo update
```

A slow scanner in the generic group does not delay language scanner startup after both wrapper goroutines are scheduled. A slow scanner in either group still delays final analysis completion because the top-level `g.Wait()` waits for both groups.

### 1c. Container Start Latency

Docker mode:

- API call to create container: `ContainerCreate` in `api/dockers/api.go:77-91`.
- API call to start container: `ContainerStart` in `api/dockers/api.go:93-97`.
- The code does not explicitly wait for `running`; after `ContainerStart`, it waits for `NotRunning` at `api/dockers/api.go:99-116`.
- Image pull happens before container creation in `api/dockers/huskydocker.go:45-51`, with a separate 15-minute retry loop at `api/dockers/huskydocker.go:89-109`.
- Image caching is checked against the Docker daemon with `ImageIsLoaded` (`api/dockers/api.go:232-246`).

Kubernetes mode:

- API call to create pod: `Pods(...).Create` in `api/kubernetes/api.go:82-150`.
- `CreatePod` returns after API acceptance, not after the pod is running.
- `WaitPod` first waits for `Running` with `podSchedulingTimeoutInSeconds`, then waits for terminal success/failure with `testTimeOutInSeconds` (`api/kubernetes/api.go:152-230`).
- Image pull is controlled by `ImagePullPolicy: PullIfNotPresent` at `api/kubernetes/api.go:113-118`, so cold-node pull and scheduling are counted in the scheduling timeout before `Running`.

### 1d. Output Collection Latency

Docker calls `ReadOutput` only after `WaitContainer` returns (`api/dockers/huskydocker.go:67-77`). `ReadOutput` then reads the entire log stream with `io.ReadAll` (`api/dockers/api.go:188-203`). Kubernetes follows the same pattern: `WaitPod` completes before `ReadOutput`, and `ReadOutput` uses `io.ReadAll` on the pod log stream (`api/kubernetes/huskykube.go:74-88`, `api/kubernetes/api.go:233-257`).

The goroutine is occupied for scanner runtime plus log retrieval plus parse time. Memory use has no pre-read bound in either mode.

## Phase 2 -- Concurrency And Throughput Ceiling Analysis

### 2a. Goroutine Budget Per Concurrent Scan

Counting goroutines spawned directly by HuskyCI scan orchestration:

- Enry fails before post-enry fan-out: `1` detached `StartAnalysis` goroutine.
- Enry succeeds but no post-enry tests: `1 + 2 = 3` goroutines.
- All registered post-enry scanners active: `1 + 2 + 16 = 19` goroutines.

The all-scanners calculation is six generic scanners (`gitauthors`, `gitleaks`, four `wizcli_*`) plus ten language scanners (`gosec`, `bandit`, `brakeman`, `safety`, `npmaudit`, `yarnaudit`, `pnpmaudit`, `spotbugs`, `tfsec`, `securitycodescan`) plus two group wrappers and the detached analysis goroutine. The HTTP request goroutine is not counted because it returns after `201`.

Go's runtime multiplexes goroutines onto OS threads, so thousands of goroutines are structurally supported. The repository does not contain enough information to identify the exact N where scheduler overhead becomes measurable. Unable to verify from static analysis — requires benchmark: `BenchmarkScanGoroutineFanout` (specified in Phase 6).

### 2b. Container Runtime As The True Throughput Ceiling

Docker mode has no shared client or shared concurrency budget. It creates a new client per scanner (`api/dockers/huskydocker.go:37-43`) and sends concurrent create/start/wait/log calls to Docker. The daemon becomes the external serialization and rate-limit point. HuskyCI does not observe daemon queue depth.

Kubernetes mode creates a clientset per scanner (`api/kubernetes/huskykube.go:49-56`) and relies on API server, scheduler, and node image cache capacity. The code does not configure `QPS`/`Burst`, and per-scanner clientsets make process-level rate control ineffective.

### 2c. MongoDB As A Throughput Multiplier

Hot-path MongoDB calls during an active scan:

| Stage | Function | Query shape | Performance risk |
|---|---|---|---|
| Request preflight | `FindOneDBRepository` | `{"$and":[{"repositoryURL": url}]}` | Collection scan without `repositoryURL` index |
| Request dedupe | `FindOneDBAnalysis` | `{"$and":[{"repositoryURL": url},{"repositoryBranch": branch}]}` | Collection scan without compound index |
| New analysis | `InsertDBAnalysis` | insert summary | Code waits for acknowledged result/error |
| Docker host rotation | `FindAndModifyDockerAPIAddresses` | `{}` + `$inc` | Small collection expected, but no explicit singleton guard |
| Enry/scanner setup | `FindOneDBSecurityTest` | `{"$and":[{"name": scanner}]}` | Repeated metadata lookup per scanner |
| Scanner list | `FindAllDBSecurityTest` | type/default or language/default | Repeated list query per scan/language |
| Final write | `UpdateOneDBAnalysisContainer` | `{"$and":[{"RID": rid}]}` | Collection scan/update without `RID` index |
| Polling | `FindOneDBAnalysis` | `{"$and":[{"RID": rid}]}` | O(N) polling read without `RID` index |

MongoDB inserts and updates are not fire-and-forget in this code: `InsertOne` and `UpdateOne` are called and their errors are returned (`api/db/mongo/mongo.go:96-107`). Write concern is not configured in code, so the exact acknowledgement level is deployment/default-driver behavior.

### 2d. Absence Of A Work Queue

When scan requests arrive faster than containers can be started, HuskyCI accepts the HTTP requests first, then lets detached goroutines pile up behind Docker/Kubernetes and MongoDB. The API returns `201` before any container/pod is running. At 10x normal load, the expected failure mode is combined goroutine growth, memory growth from scanner outputs/results, and container runtime saturation. The existing same-URL/same-branch check is not a throughput control.

## Phase 3 -- Memory Pressure Analysis

### 3a. Per-Scan Allocation Profile

Heap retained until scan completion includes:

- `RunAllInfo` and its result slices (`api/securitytest/run.go:15-33`).
- One `SecTestScanInfo` per scanner goroutine, including `Container.COutput`, `FinalOutput`, and vulnerability slices (`api/securitytest/securitytest.go:41-67`).
- Full scanner stdout/stderr log string, created by `io.ReadAll` plus `string(body)` in Docker/Kubernetes readers.
- Parser output structs, for example `SpotBugsOutput.SpotBugsIssue []SpotBugsIssue` (`api/securitytest/spotbugs.go:24-69`) and WizCLI nested result arrays (`api/securitytest/wizcli.go:15-123`).
- Aggregated `HuskyCIResults` vulnerability arrays (`api/types/types.go:95-160`).
- BSON encoding buffers during final MongoDB update.

Minimum retained heap for a failed enry path is the analysis worker, enry scan metadata, and the enry output/error. Maximum heap is unbounded by code because scanner output and vulnerability arrays have no pre-parse limit. Unable to verify from static analysis — requires benchmark: `BenchmarkReadOutputBuffering` (specified in Phase 6). Unable to verify from static analysis — requires benchmark: `BenchmarkAnalysisBSONEncodingWorstCase` (specified in Phase 6).

### 3b. Unbounded Stdout Buffer

There is no read cap in Docker or Kubernetes log readers. The only cap is `cOutputMaxSize := 1000000` after output has already been read and usually parsed (`api/securitytest/securitytest.go:178-189`). A pathological scanner output can allocate until process memory is exhausted. For scanner output of size `S`, static code shows at least `S` for the `io.ReadAll` byte slice plus `S` for `string(body)` plus another `S` for parser conversions such as `[]byte(scanInfo.Container.COutput)`, before parsed result objects and vulnerability slices are counted.

### 3c. Document Size Growth In MongoDB

`types.Analysis` embeds `Containers[]`, `Codes[]`, and `HuskyCIResults` (`api/types/types.go:32-46`). MongoDB enforces a 16 MiB BSON document limit. HuskyCI has no field-level limit on number of vulnerabilities, number of files in `Codes`, or length of `errorFound`. A large scan can approach the limit even after `Container.COutput` is truncated to a short message.

The `io.ReadAll` buffer and MongoDB BSON document do not share backing data in a way that avoids allocation; the code converts and copies between bytes, strings, structs, and BSON encoding.

## Phase 4 -- Degradation And Saturation Behaviour

### 4a. Failure Cascade Under Docker Saturation

First observable symptom: accepted scans continue returning `201`, while scanner goroutines accumulate in Docker client calls and `WaitContainer` (`api/routes/analysis.go:160`, `api/dockers/huskydocker.go:53-77`, `api/dockers/api.go:99-116`). Without metrics, the only visible signals are higher API memory, goroutine count if manually profiled, and delayed `GET /analysis/:id` completion.

Second failure: memory pressure increases from active scan structs and log buffers, while Docker daemon/container capacity saturates. If Docker mode hits hung containers, prior finding #2 prevents deadline recovery.

Steady-state failure mode: total throughput collapse rather than graceful degradation. The service has no queue, no circuit breaker, no 429/503 admission control, and no graceful shutdown cleanup (`api/server.go:23-110`).

### 4b. MongoDB Degradation Path

`FindOneDBAnalysis` in request acceptance becomes dominant when collection-scan latency exceeds validation and token-check latency. The collection size where that happens cannot be derived from code because it depends on document size, RAM/cache, storage, and MongoDB deployment. The growth function is O(N) under prior finding #11. Unable to verify from static analysis — requires benchmark: `BenchmarkMongoAnalysisQueries` (specified in Phase 6).

Reconnect behavior cannot be determined statically. `autoReconnect` may disconnect the shared client while in-flight operations are running (`api/db/mongo/mongo.go:76-94`), and all operations use `context.TODO()` (`api/db/mongo/mongo.go:96-174`). Unable to verify from static analysis — requires benchmark: `BenchmarkMongoReconnectDuringScan` (specified in Phase 6).

### 4c. Polling Amplification

MongoDB read load from polling is:

```text
reads_per_second = concurrent_scans * (1 / poll_interval_seconds)
```

At 100 concurrent scans with a 5-second poll interval, the formula is `100 * (1 / 5) = 20 reads/second`; at 1,000 concurrent scans with a 5-second interval, it is `200 reads/second`. These are formula outputs, not measured throughput estimates. Polling becomes dominant when this read rate exceeds scan-start and scan-finalization DB operation rates.

`FindOneDBAnalysis` is not indexed on `RID` in source because `api/db/mongo/mongo.go` declares no indexes. The query shape is `{"RID": RID}` at `api/routes/analysis.go:53-55`, converted to `$and` in `api/db/huskydb.go:61-72`.

## Phase 5 -- Observability Gap Assessment

All required signals are absent today.

| Signal | Performance question answered | Code location to instrument | Metric name | Type | Labels | Present? |
|---|---|---|---|---|---|---|
| Scan request rate | How much work is being admitted? | `api/routes/analysis.go::ReceiveRequest` entry | `huskyci_scan_requests_total` | Counter | none | Absent |
| In-flight scan count | How much background scan work is active? | `api/analysis/analysis.go::StartAnalysis` start/end | `huskyci_inflight_scans` | Gauge | none | Absent |
| Scan duration | What is end-to-end scan latency by runtime mode? | `run.go::Start()` through `registerFinishedAnalysis` | `huskyci_scan_duration_seconds` | Histogram | `scanner_mode` | Absent |
| Per-scanner duration | Which scanner dominates the critical path? | Each scanner `g.Go` body in `run.go` | `huskyci_scanner_duration_seconds` | Histogram | `scanner_name` | Absent |
| Container start latency | Is Docker/K8s startup the bottleneck? | Docker/K8s create/start or create/running | `huskyci_container_start_duration_seconds` | Histogram | `scanner_name`, `mode` | Absent |
| Output bytes read | Are scanner logs causing memory pressure? | `dockers/api.go::ReadOutput`, `kubernetes/api.go::ReadOutput` | `huskyci_scanner_output_bytes` | Histogram | `scanner_name`, `mode` | Absent |
| MongoDB query duration | Are DB reads/writes dominating request or scan latency? | Each DB wrapper in `huskydb.go`/`mongo.go` | `huskyci_mongodb_operation_duration_seconds` | Histogram | `operation`, `collection` | Absent |
| Active goroutine count | Is fan-out accumulating faster than work drains? | Runtime telemetry | `huskyci_active_goroutines` | Gauge | none | Absent |
| Docker daemon error rate | Is Docker rejecting or failing container lifecycle calls? | `ContainerCreate` / `ContainerStart` error paths | `huskyci_docker_errors_total` | Counter | `operation`, `error_type` | Absent |

Minimum Prometheus dependency path to add to `api/go.mod`:

```go
github.com/prometheus/client_golang
```

Suggested metrics package:

```go
package metrics

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ScanRequestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "huskyci_scan_requests_total",
		Help: "Total scan requests accepted by ReceiveRequest.",
	})
	InFlightScans = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "huskyci_inflight_scans",
		Help: "Current number of active scan analyses.",
	})
	ScanDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "huskyci_scan_duration_seconds",
		Help:    "End-to-end scan duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"scanner_mode"})
	ScannerDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "huskyci_scanner_duration_seconds",
		Help:    "Per-scanner execution duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"scanner_name"})
	ContainerStartDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "huskyci_container_start_duration_seconds",
		Help:    "Container or pod create-to-running latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"scanner_name", "mode"})
	OutputBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "huskyci_scanner_output_bytes",
		Help:    "Bytes read from scanner stdout/logs.",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
	}, []string{"scanner_name", "mode"})
	MongoDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "huskyci_mongodb_operation_duration_seconds",
		Help:    "MongoDB operation duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation", "collection"})
	ActiveGoroutines = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "huskyci_active_goroutines",
		Help: "Current goroutine count from runtime.NumGoroutine.",
	}, func() float64 {
		return float64(runtime.NumGoroutine())
	})
	DockerErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "huskyci_docker_errors_total",
		Help: "Docker daemon errors by operation and error type.",
	}, []string{"operation", "error_type"})
)

func init() {
	prometheus.MustRegister(
		ScanRequestsTotal,
		InFlightScans,
		ScanDurationSeconds,
		ScannerDurationSeconds,
		ContainerStartDurationSeconds,
		OutputBytes,
		MongoDurationSeconds,
		ActiveGoroutines,
		DockerErrorsTotal,
	)
}
```

Expose `/metrics` in `api/server.go`:

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

echoInstance.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
```

Emit scan request rate at `ReceiveRequest` entry:

```go
metrics.ScanRequestsTotal.Inc()
```

Emit in-flight scans and scan duration in `StartAnalysis`:

```go
func StartAnalysis(RID string, repository types.Repository) {
	start := time.Now()
	metrics.InFlightScans.Inc()
	defer metrics.InFlightScans.Dec()
	defer func() {
		mode := os.Getenv("HUSKYCI_INFRASTRUCTURE_USE")
		metrics.ScanDurationSeconds.WithLabelValues(mode).Observe(time.Since(start).Seconds())
	}()
	// existing body
}
```

Emit per-scanner duration inside each scanner goroutine in `run.go`:

```go
started := time.Now()
err := runner.startScan(scan)
metrics.ScannerDurationSeconds.WithLabelValues(testName).Observe(time.Since(started).Seconds())
if err != nil {
	return err
}
```

Emit container start latency in Docker and Kubernetes wrappers:

```go
started := time.Now()
CID, err := d.CreateContainer(fullContainerImage, cmd)
if err != nil { return "", "", err }
d.CID = CID
if err := d.StartContainer(); err != nil { return "", "", err }
metrics.ContainerStartDurationSeconds.WithLabelValues(scannerName, "docker").Observe(time.Since(started).Seconds())
```

```go
started := time.Now()
podUID, err := k.CreatePod(fullContainerImage, cmd, podName, securityTestName)
if err != nil { return "", "", err }
_, err = k.WaitPod(podName, podSchedulingTimeoutInSeconds, timeOutInSeconds)
metrics.ContainerStartDurationSeconds.WithLabelValues(securityTestName, "kubernetes").Observe(time.Since(started).Seconds())
```

Emit output bytes read in both `ReadOutput` implementations:

```go
body, err := io.ReadAll(out)
metrics.OutputBytes.WithLabelValues(scannerName, "docker").Observe(float64(len(body)))
```

Emit MongoDB operation duration in each wrapper:

```go
started := time.Now()
err := mongoHuskyCI.Conn.SearchOne(query, nil, mongoHuskyCI.AnalysisCollection, &analysisResponse)
metrics.MongoDurationSeconds.WithLabelValues("find_one_analysis", mongoHuskyCI.AnalysisCollection).Observe(time.Since(started).Seconds())
return analysisResponse, err
```

Emit Docker daemon error rate:

```go
if err != nil {
	metrics.DockerErrorsTotal.WithLabelValues("container_create", classifyDockerError(err)).Inc()
	return "", err
}
```

## Phase 6 -- Benchmarks That Must Be Written

```text
Benchmark name: BenchmarkMongoAnalysisQueries
File: api/db/mongo/mongo_bench_test.go
What it measures: FindOneDBAnalysis and UpdateOneDBAnalysisContainer latency as analysis collection size grows.
Setup: Test MongoDB instance seeded with 1k, 10k, and 100k analysis documents; run with and without proposed indexes.
Input range: Sub-benchmarks docs=1k/10k/100k and query=RID/url_branch/url_branch_status/update_RID.
Expected result: Indexed queries stay structurally O(1)/O(log N); unindexed current queries grow linearly.
Regression threshold: Flag if indexed P99 exceeds 50ms or if docs examined exceeds expected index bounds.
Gap analysis reference: prior finding #11.
```

```text
Benchmark name: BenchmarkReadOutputBuffering
File: api/dockers/api_bench_test.go
What it measures: io.ReadAll throughput, allocations, and peak RSS for scanner output sizes.
Setup: Replace Docker log stream with an io.Reader generating 1MB, 10MB, and 100MB outputs; benchmark current read-all and proposed capped reader.
Input range: size=1MB/10MB/100MB, mode=current/capped.
Expected result: Capped reader has bounded allocations; current implementation allocations grow linearly with output size and include byte-to-string copy cost.
Regression threshold: Flag if capped mode allocs/op exceeds configured cap + 10% or if current mode is still used in production path.
Gap analysis reference: unbounded stdout buffer, prior finding #3 memory consequence.
```

```text
Benchmark name: BenchmarkScanGoroutineFanout
File: api/securitytest/run_bench_test.go
What it measures: Goroutine count, allocations, and completion overhead per scan at concurrent scan counts.
Setup: Use mockRunner with configurable generic/language scanner counts and blocking no-op scanners; sample runtime.NumGoroutine before/during/after.
Input range: concurrent_scans=1/10/50 and scanners_per_scan=1/6/16.
Expected result: With limits, goroutine count stays near baseline + configured concurrency; current implementation grows with scans x scanners.
Regression threshold: Flag if goroutines exceed configured limit + 20% or allocs/op grows unexpectedly after limits.
Gap analysis reference: prior finding #3.
```

```text
Benchmark name: BenchmarkErrgroupFanout
File: api/securitytest/run_bench_test.go
What it measures: errgroup fan-out overhead for mock scanner counts.
Setup: mockRunner returns N scanners with no-op startScan; no Docker/K8s/Mongo.
Input range: N=1..20 mock scanners, with and without errgroup.SetLimit.
Expected result: Limited fan-out adds small coordination overhead while bounding concurrency.
Regression threshold: Flag if SetLimit overhead exceeds 10% for N<=20 in no-op case.
Gap analysis reference: prior finding #3.
```

```text
Benchmark name: BenchmarkAnalysisBSONEncodingWorstCase
File: api/analysis/analysis_bench_test.go
What it measures: BSON encoding time and allocation size for worst-case Analysis documents.
Setup: Build types.Analysis with max realistic Containers, Codes, and HuskyCIResults vulnerability arrays; encode with mongo-driver BSON.
Input range: vulnerabilities=1k/10k/50k and cOutput sizes=0/1MB placeholder/errorFound prefix.
Expected result: Encoding remains below MongoDB 16 MiB limit or fails early with a controlled error before DB update.
Regression threshold: Flag if BSON size exceeds 14 MiB warning threshold or allocs/op exceeds document size x 3.
Gap analysis reference: prior finding #11 document size.
```

```text
Benchmark name: BenchmarkCheckMaliciousRepoURLConcurrent
File: api/util/util_bench_test.go
What it measures: Throughput and allocations of CheckMaliciousRepoURL under concurrent request validation.
Setup: Valid and invalid repository URL corpus; compare current per-call regexp compilation with package-level compiled regexp.
Input range: b.RunParallel with corpus sizes 10/100/1000.
Expected result: Precompiled regex reduces allocations/op and CPU/op without changing accepted/rejected outputs.
Regression threshold: Flag if allocs/op > 2 after precompilation or if any corpus result changes.
Gap analysis reference: new low-severity regex CPU gap.
```

```text
Benchmark name: BenchmarkMongoReconnectDuringScan
File: api/db/mongo/mongo_bench_test.go
What it measures: Mongo operation latency and error behavior while reconnect runs during active scan DB operations.
Setup: Test MongoDB or controllable fake server; active goroutines issue FindOne/Update operations while connection is interrupted.
Input range: concurrent_operations=1/10/50, interruption_duration=1s/5s.
Expected result: Operations fail or recover within configured DB deadlines once deadlines are implemented.
Regression threshold: Flag if any operation blocks beyond DB timeout or leaks goroutines.
Gap analysis reference: reconnect latency under prior finding #11.
```

## Performance Strengths

- **Request acceptance is asynchronous.** `ReceiveRequest` returns after spawning `StartAnalysis` (`api/routes/analysis.go:160-162`), so HTTP clients are not held for full scanner duration.
- **Generic and language scanner groups start concurrently.** The top-level errgroup launches both group functions before waiting (`api/securitytest/run.go:67-76`).
- **Kubernetes scanner execution has explicit timeout watches.** `WaitPod` uses `TimeoutSeconds` for scheduling and execution phases (`api/kubernetes/api.go:152-230`).
- **Kubernetes image policy uses node cache when available.** `ImagePullPolicy: core.PullIfNotPresent` is set in `api/kubernetes/api.go:113-118`.
- **Concurrent result aggregation is mutex-protected.** `RunAllInfo.mu` guards appends and vulnerability aggregation in `api/securitytest/run.go:114-122` and `api/securitytest/run.go:160-179`.
- **Stored container output has a post-read cap.** `prepareContainerAfterScan` replaces `COutput` when it exceeds 1,000,000 bytes (`api/securitytest/securitytest.go:178-189`). This does not solve pre-read memory pressure, but it reduces MongoDB document growth for successful paths.
- **MongoDB writes are not fire-and-forget in code.** `InsertOne` and `UpdateOne` return errors and callers propagate them (`api/db/mongo/mongo.go:96-107`).
- **MongoDB auto-reconnect exists as a limited recovery mechanism.** `autoReconnect` pings every second and reconnects on error (`api/db/mongo/mongo.go:76-94`). This is useful for transient connectivity, but its latency impact on in-flight queries is not statically verifiable and is covered by `BenchmarkMongoReconnectDuringScan`.
- **CI runs the race detector.** `.github/workflows/ci.yaml:36-38` runs `go test -race -count=1 ./...`, which can catch performance-relevant data races in concurrent aggregation.

## Prioritised Remediation Roadmap

### Immediate (0-30 days)

| Item | Effort | Expected throughput impact | Benchmark verification |
|---|---:|---|---|
| Add global scan/scanner concurrency limits and return 429/503 when saturated | 3-5 days | Prevents total saturation from bursty request traffic | `BenchmarkScanGoroutineFanout`, `BenchmarkErrgroupFanout` |
| Fix Docker `WaitContainer` timeout and cleanup on timeout | 1-2 days | Prevents indefinite Docker-mode resource retention | Integration timeout test; no benchmark needed |
| Cap Docker and Kubernetes log reads before `io.ReadAll`/string conversion | 2-3 days | Prevents OOM from large scanner output | `BenchmarkReadOutputBuffering` |
| Add MongoDB indexes on `analysis.RID`, active URL/branch/status, and `repository.repositoryURL` | 1-2 days | Restores hot-path query growth from O(N) toward indexed lookup behavior | `BenchmarkMongoAnalysisQueries` |
| Add minimal Prometheus `/metrics` with request, in-flight, duration, output bytes, Mongo, goroutine, and Docker error metrics | 3-5 days | Makes saturation visible before outage | Operational validation plus benchmark labels |

### Near-term (30-90 days)

| Item | Effort | Expected throughput impact | Benchmark verification |
|---|---:|---|---|
| Share Docker clients per host and Kubernetes clientset per process with explicit QPS/Burst | 1 week | Reduces client churn and enables runtime-level request budgeting | Docker/K8s burst benchmarks |
| Move scanner metadata reads out of the hot path into startup cache | 3-5 days | Removes repeated DB reads per scanner | `BenchmarkMongoAnalysisQueries` |
| Split large scanner findings from the analysis summary document | 1-2 weeks | Avoids BSON 16 MiB cliff and reduces final update latency | `BenchmarkAnalysisBSONEncodingWorstCase` |
| Add per-operation MongoDB contexts with deadlines | 3-5 days | Bounds latency during collection scans/reconnect/server stalls | `BenchmarkMongoReconnectDuringScan` |
| Add server-side polling controls (`Retry-After`, rate limits, optional long polling) | 1 week | Reduces read amplification from clients | `BenchmarkMongoAnalysisQueries` plus load test |

### Long-term (90+ days)

| Item | Effort | Expected throughput impact | Benchmark verification |
|---|---:|---|---|
| Introduce durable scan queue with workers and explicit capacity policy | 3-6 weeks | Converts overload from collapse to controlled queueing/rejection | End-to-end load benchmark |
| Add OpenTelemetry traces from request acceptance through scanner lifecycle and MongoDB operations | 2-4 weeks | Enables P95/P99 root-cause attribution | Trace completeness checks |
| Add a stale-analysis and orphaned-container/pod reaper | 1-2 weeks | Recovers capacity after restart or crash | Integration failure-injection tests |
| Establish performance benchmark suite in CI/nightly runs | 2-3 weeks | Prevents regression in fan-out, Mongo, output buffering, and BSON encoding | All Phase 6 benchmarks |
| Revisit result storage model and retention/TTL policy | 2-4 weeks | Controls long-term collection size and polling latency | `BenchmarkMongoAnalysisQueries`, storage growth checks |

## External Primary References Consulted

- Go documentation: goroutines are multiplexed onto OS threads.
- MongoDB manual: `COLLSCAN`, documents examined, and 16 MiB BSON document limit.
- Kubernetes `client-go/rest` package documentation: `DefaultQPS = 5.0`, `DefaultBurst = 10`.
- Prometheus `client_golang` package documentation: Counter, Gauge, HistogramVec, and `promhttp.Handler`.
