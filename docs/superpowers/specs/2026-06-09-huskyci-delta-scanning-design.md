# HuskyCI Delta Scanning Design

> **Status:** Design approved. Implementation pending.
> **Date:** 2026-06-09

## Goal

Reduce HuskyCI scan wall-clock time on PRs by scanning only changed files instead of the entire repository. For a typical PR with 5 changed files on a 234MB monorepo, wall clock drops from ~180s to ~120s (vulns still needs full clone).

## Architecture

### Data Flow

```
.github SAST workflow
  actions/checkout (fetch-depth: 0)
  git diff --name-only origin/${{ github.base_ref }}...HEAD
  export HUSKYCI_CLIENT_CHANGED_FILES (newline-separated)
       ↓
HuskyCI client container
  reads HUSKYCI_CLIENT_CHANGED_FILES env var
  adds to JSONPayload.ChangedFiles
  POST /analysis
       ↓
HuskyCI API
  stores in Repository.ChangedFiles
  HandleCmd() replaces %CHANGED_FILES% with the list
  creates pods with HUSKYCI_DELTA_SCAN=true env var (if deltaScan: true in config)
       ↓
Scanner pod
  if HUSKYCI_DELTA_SCAN=true AND %CHANGED_FILES% non-empty:
    git clone --no-checkout → git sparse-checkout set <files> → scan
  else:
    git clone --depth 1 (full clone, as today)
```

### Delta-capable scanners

| Scanner | Delta? | Rationale |
|---|---|---|
| `wizcli_secrets` | ✅ Yes | Only changed files can introduce new secrets |
| `wizcli_iac` | ✅ Yes | Only changed IaC files can introduce new misconfigs |
| `wizcli_sast` | ✅ Yes | Only changed code has new vulnerabilities |
| `gitleaks` | ✅ Yes | Same as secrets |
| `bandit` | ✅ Yes | Python static analysis on changed files |
| `gosec` | ✅ Yes | Go static analysis on changed files |
| `brakeman` | ✅ Yes | Ruby static analysis on changed files |
| `wizcli_vulns` | ❌ No | Needs full lockfile for dependency resolution |
| `npmaudit` | ❌ No | Needs full lockfile for npm registry query |
| `yarnaudit` | ❌ No | Needs full lockfile for yarn registry query |
| `pnpmaudit` | ❌ No | Needs full lockfile for pnpm registry query |
| `spotbugs` | ❌ No | Needs compiled artifacts |
| `safety` | ❌ No | Needs full requirements.txt |
| `tfsec` | ❌ No | Needs all .tf files for context |
| `securitycodescan` | ❌ No | Needs full .sln context |
| `enry` | ❌ No | Must detect ALL languages |
| `gitauthors` | ❌ No | Metadata, not file-based |

## Detailed Changes

### 1. `api/config.yaml`

No changes needed. The `deltaScan` field is NOT added to config.yaml. Instead, delta scanning is controlled via environment variables on the API pod, following the existing `HUSKYCI_DISABLE_<TESTNAME>` pattern.

### 2. Delta scan env vars (API pod)

New env vars set on the API pod via Helm `values.yaml`:

```
HUSKYCI_DELTA_SCAN_WIZCLI_SECRETS=true
HUSKYCI_DELTA_SCAN_WIZCLI_IAC=true
HUSKYCI_DELTA_SCAN_WIZCLI_SAST=true
HUSKYCI_DELTA_SCAN_GITLEAKS=true
HUSKYCI_DELTA_SCAN_BANDIT=true
HUSKYCI_DELTA_SCAN_GOSEC=true
HUSKYCI_DELTA_SCAN_BRAKEMAN=true
```

Set in `k8s-infrastructure-live/components/huskyci/unreleased/values.yaml`:

```yaml
env:
  HUSKYCI_DELTA_SCAN_WIZCLI_SECRETS: "true"
  HUSKYCI_DELTA_SCAN_WIZCLI_IAC: "true"
  HUSKYCI_DELTA_SCAN_WIZCLI_SAST: "true"
  HUSKYCI_DELTA_SCAN_GITLEAKS: "true"
  HUSKYCI_DELTA_SCAN_BANDIT: "true"
  HUSKYCI_DELTA_SCAN_GOSEC: "true"
  HUSKYCI_DELTA_SCAN_BRAKEMAN: "true"
```

The API reads these env vars when creating scanner pods. If the env var is set to `"true"`, the API adds `HUSKYCI_DELTA_SCAN=true` to the scanner pod's environment. This matches how `HUSKYCI_DISABLE_<TESTNAME>` already works in `isTestDisabled()`.

**Scanner cmd scripts** check `HUSKYCI_DELTA_SCAN` as before. No config.yaml changes needed.

### 3. `api/types/types.go`

```go
type Repository struct {
    // ... existing fields ...
    ChangedFiles string `json:"changedFiles"`  // NEW — newline-separated
}
```

No changes to `SecurityTest` — delta scanning is controlled by env vars, not config fields.

### 4. `api/util/util.go`

```go
func HandleCmd(repositoryURL, repositoryBranch, cmd, changedFiles string) string {
    // ... existing replaces for %GIT_REPO%, %GIT_BRANCH%, %WIZ_CLIENT_ID%, %WIZ_CLIENT_SECRET% ...
    replace5 := strings.ReplaceAll(replace4, "%CHANGED_FILES%", changedFiles)
    return replace5
}
```

All callers of `HandleCmd` must pass the new `changedFiles` argument (empty string when no delta).

### 5. `api/kubernetes/huskykube.go`

```go
func isDeltaScanEnabled(securityTestName string) bool {
    envVarName := "HUSKYCI_DELTA_SCAN_" + strings.ToUpper(securityTestName)
    return strings.ToLower(os.Getenv(envVarName)) == "true"
}

func KubeRun(image, imageTag, cmd, securityTestName, id string,
    podSchedulingTimeoutInSeconds, timeOutInSeconds int) (string, string, error) {

    // In pod spec creation:
    envVars := []core.EnvVar{}
    if isDeltaScanEnabled(securityTestName) {
        envVars = append(envVars, core.EnvVar{Name: "HUSKYCI_DELTA_SCAN", Value: "true"})
    }
    // ... set pod.Spec.Containers[0].Env = envVars ...
}
```

Matches the existing `isTestDisabled()` pattern — reads `HUSKYCI_DELTA_SCAN_<UPPERCASE_NAME>` from the API pod's environment.

### 6. Scanner cmd scripts (`api/config.yaml`)

Each delta-capable scanner's cmd block adds conditional sparse-checkout BEFORE the existing scanner logic:

```sh
# ... SSH setup ...

if [ "$HUSKYCI_DELTA_SCAN" = "true" ] && [ -n "%CHANGED_FILES%" ]; then
  # Delta mode: sparse checkout of changed files only
  GIT_TERMINAL_PROMPT=0 git clone --no-checkout -b "%GIT_BRANCH%" --single-branch --depth 1 "%GIT_REPO%" code --quiet 2>/tmp/errorGitClone
  if [ $? -eq 0 ]; then
    cd code
    git sparse-checkout init --cone
    echo "%CHANGED_FILES%" | xargs git sparse-checkout set
    git checkout 2>/tmp/errorSparseCheckout
    if [ $? -ne 0 ]; then
      echo "ERROR_SPARSE_CHECKOUT"
      cat /tmp/errorSparseCheckout
      exit 1
    fi
  else
    echo "ERROR_CLONING"
    cat /tmp/errorGitClone
    exit 1
  fi
else
  # Full clone (as today)
  GIT_TERMINAL_PROMPT=0 git clone -b "%GIT_BRANCH%" --single-branch --depth 1 "%GIT_REPO%" code --quiet 2>/tmp/errorGitClone
  if [ $? -ne 0 ]; then
    echo "ERROR_CLONING"
    cat /tmp/errorGitClone
    exit 1
  fi
fi

# ... existing scanner logic continues (cd code, run tool) ...
```

Scanners that DON'T support delta keep their existing cmd blocks unchanged — no conditional branch, just the full clone path.

### 7. Client

**`client/config/config.go`:**
```go
var ChangedFiles = os.Getenv("HUSKYCI_CLIENT_CHANGED_FILES")
```

**`client/types/types.go`:**
```go
type JSONPayload struct {
    // ... existing fields ...
    ChangedFiles string `json:"changedFiles"`
}
```

**`client/analysis/analysis.go`:**
```go
requestPayload := types.JSONPayload{
    // ...
    ChangedFiles: config.ChangedFiles,
}
```

### 6. `.github/workflows/anotaai-sast.yml`

Add step BEFORE the huskyci client container, inside the `huskyci` job:

```yaml
- name: Compute changed files (PR delta)
  if: github.event_name == 'pull_request'
  run: |
    git diff -z --name-only --diff-filter=AM origin/${{ github.base_ref }}...HEAD > /tmp/changed.txt
    if [ -s /tmp/changed.txt ]; then
      CHANGED=$(tr '\0' '\n' < /tmp/changed.txt)
      echo "CHANGED_FILES=$CHANGED" >> $GITHUB_ENV
    fi
```
# Existing client container step, add env:
# HUSKYCI_CLIENT_CHANGED_FILES: ${{ env.CHANGED_FILES }}
```

`--diff-filter=AM` excludes deleted files (which sparse-checkout can't restore).

## Edge Cases

| Case | Behavior |
|---|---|
| Push event (non-PR) | `CHANGED_FILES` empty → all scanners full clone |
| First PR (no base ref) | `git diff` empty → full clone |
| Deleted files | `--diff-filter=AM` excludes them from the list |
| Spaces in file names | `git diff -z --name-only` + null-separated processing (use `xargs -0`) |
| Sparse checkout fails | Scanner emits `ERROR_SPARSE_CHECKOUT` → pod fails → API logs error. No fallback to full clone (keeps complexity low). |
| Scanner not delta-capable | `deltaScan` absent or false → no `HUSKYCI_DELTA_SCAN` env var → full clone always |
| `%CHANGED_FILES%` literal in cmd | If HandleCmd not called with changed files, placeholder remains → shell sees literal string, treats as non-empty → might fail. Mitigation: HandleCmd always called with empty string default. |

## Performance Impact

**Typical PR (5 files, 234MB monorepo):**

| Scanner | Before (clone+scan) | After (delta) |
|---|---|---|
| wizcli_secrets | 60s + 30s = 90s | 2s + 5s = **7s** |
| wizcli_iac | 60s + 40s = 100s | 2s + 10s = **12s** |
| wizcli_sast | 60s + 50s = 110s | 2s + 10s = **12s** |
| gitleaks | 60s + 10s = 70s | 2s + 3s = **5s** |
| wizcli_vulns | 60s + 120s = 180s | 60s + 120s = 180s (no delta) |

Wall clock: 180s → **180s** (still driven by vulns). But resource usage drops dramatically: 4 fewer full clones = ~240MB less network traffic per analysis.

**Infra-only PR (0 deps, only .tf/.yaml changes):**

Wall clock: 180s → **12s** (vulns not triggered since no lockfiles to scan — enry detects no JavaScript/Python/Java).

## Not in Scope

- Shared clone volume (init container pattern) — separate project
- Repo-level clone cache — separate project
- Delta scanning for npm/yarn/pnpm audit — these need full lockfile, but could be explored later with lockfile diffing
- Automatic delta-capability detection — scanners are explicitly opted in via Helm env vars
