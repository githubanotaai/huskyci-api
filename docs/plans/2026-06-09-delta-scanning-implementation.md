# Delta Scanning Implementation Plan

> **For Hermes:** Use the kanban-orchestrator pattern — each phase is a Kanban card dispatched to an exclusive subagent. Phases are hard-blocks (sequential, each depends on the previous phase completing successfully).

> **Spec:** `docs/superpowers/specs/2026-06-09-huskyci-delta-scanning-design.md`

**Goal:** Implement PR delta scanning — scanners clone only changed files instead of the entire repository. Controlled via Helm `scanners:` configuration block.

**Architecture:** Changed files flow from GitHub Actions workflow → client env var → API payload → `%CHANGED_FILES%` template placeholder → scanner pod `sparse-checkout`. Opt-in per scanner via `HUSKYCI_SCANNER_<NAME>_DELTA_SCAN=true` env var set by Helm chart.

**Tech Stack:** Go (API types, util, huskykube), Bash (scanner cmd scripts), YAML (Helm values, GitHub Actions), Go (client)

**Repos involved:** `huskyci-api`, `k8s-infrastructure-live`, `.github`

---

## Phase 1: API Core — types, util, huskykube

**Hard-block for:** Phase 2 (scanner cmds depend on `%CHANGED_FILES%` and `HUSKYCI_DELTA_SCAN` env var)

**Kanban card:** `phase-1-api-core`

**Files:**
- Modify: `api/types/types.go` — add `ChangedFiles string` to `Repository`
- Modify: `api/util/util.go` — add `%CHANGED_FILES%` to `HandleCmd`, update all callers
- Modify: `api/kubernetes/huskykube.go` — add `isDeltaScanEnabled()`, `getScannerConfig()`, pass `HUSKYCI_DELTA_SCAN` env var to pods
- Create: `api/util/util_test.go` — test `HandleCmd` with `%CHANGED_FILES%`
- Create: `api/kubernetes/huskykube_test.go` — test `isDeltaScanEnabled` and `getScannerConfig`

**Key implementation notes:**
- `HandleCmd` signature changes: add `changedFiles string` parameter. Update ALL callers (check `securitytest/securitytest.go` where `HandleCmd` is called during pod creation).
- `isDeltaScanEnabled()` reads `HUSKYCI_SCANNER_<NAME>_DELTA_SCAN` via `getScannerConfig()`, returns true if `"true"` (case-insensitive).
- `getScannerConfig(securityTestName, key string) string` reads `HUSKYCI_SCANNER_<UPPERNAME>_<KEY>` from env.
- `KubeRun` adds `HUSKYCI_DELTA_SCAN=true` to pod env vars if `isDeltaScanEnabled()`.

**Verification:** `cd api && go build ./... && go test ./util/... ./kubernetes/...` — all pass.

---

## Phase 2: Scanner Cmd Scripts

**Hard-block for:** Phase 3 (client must send changed files for scanners to use)

**Kanban card:** `phase-2-scanner-cmds`

**Files:**
- Modify: `api/config.yaml` — add sparse-checkout conditional to 7 delta-capable scanners: `wizcli_secrets`, `wizcli_iac`, `wizcli_sast`, `gitleaks`, `bandit`, `gosec`, `brakeman`

**Cmd pattern to insert BEFORE the existing `cd code` step (after SSH setup):**

```sh
if [ "$HUSKYCI_DELTA_SCAN" = "true" ] && [ -n "%CHANGED_FILES%" ]; then
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
  GIT_TERMINAL_PROMPT=0 git clone -b "%GIT_BRANCH%" --single-branch --depth 1 "%GIT_REPO%" code --quiet 2>/tmp/errorGitClone
  if [ $? -ne 0 ]; then
    echo "ERROR_CLONING"
    cat /tmp/errorGitClone
    exit 1
  fi
fi
```

**Important:** The `else` branch must keep the EXISTING full clone command exactly as-is (preserving error log filenames like `errorGitCloneWiz`, `errorGitCloneGitleaks`, etc.). The delta branch uses a generic `errorGitClone` log file since `--no-checkout` can't have the same semantics.

**8 scanners NOT modified:** `wizcli_vulns`, `npmaudit`, `yarnaudit`, `pnpmaudit`, `spotbugs`, `safety`, `tfsec`, `securitycodescan`, `enry`, `gitauthors` — keep existing cmd blocks unchanged.

**Verification:** `python3 -c "import yaml; yaml.safe_load(open('api/config.yaml')); print('YAML valid')"` and visually verify each modified scanner has both delta and full-clone paths.

---

## Phase 3: Client Changes

**Hard-block for:** Phase 4 (workflow exports env var that client reads)

**Kanban card:** `phase-3-client`

**Files:**
- Modify: `client/config/config.go` — add `var ChangedFiles = os.Getenv("HUSKYCI_CLIENT_CHANGED_FILES")`
- Modify: `client/types/types.go` — add `ChangedFiles string \`json:"changedFiles"\`` to `JSONPayload`
- Modify: `client/analysis/analysis.go` — add `ChangedFiles: config.ChangedFiles` to `requestPayload`
- Create: `client/analysis/analysis_test.go` — test that `ChangedFiles` is included in request payload when env var is set

**Verification:** `cd client && go build ./... && go test ./analysis/...` — all pass.

---

## Phase 4: GitHub Workflow

**Hard-block for:** Phase 5 (Helm values reference the client image tag)

**Kanban card:** `phase-4-workflow`

**Files:**
- Modify: `.github/workflows/anotaai-sast.yml` (in `.github` org repo) — add step to compute changed files

**Step to add BEFORE the existing `huskyci` container step:**

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

**Add env to the existing client container:**
```yaml
HUSKYCI_CLIENT_CHANGED_FILES: ${{ env.CHANGED_FILES }}
```

**Repo:** `githubanotaai/.github` (branch from master, separate PR targeting master). Also cherry-pick to develop.

**Verification:** Review the workflow YAML for syntax. No runtime test possible without merging.

---

## Phase 5: Helm Chart + Values

**Hard-block for:** Phase 6 (E2E tests need the Helm config deployed)

**Kanban card:** `phase-5-helm`

**Files:**
- Modify: `k8s-infrastructure-live/components/huskyci/unreleased/values.yaml` — add `scanners:` block
- Modify: `k8s-infrastructure-live/components/huskyci/unreleased/Chart.yaml` — bump `version: 0.4.0` → `0.5.0`
- Modify: Helm chart template (`templates/deployment.yaml` or similar) — add logic to expand `scanners:` YAML block into flat `HUSKYCI_SCANNER_<NAME>_<KEY>` env vars

**`scanners:` block to add:**

```yaml
scanners:
  wizcli_secrets:
    enabled: true
    deltaScan: true
  wizcli_iac:
    enabled: true
    deltaScan: true
  wizcli_sast:
    enabled: true
    deltaScan: true
  gitleaks:
    enabled: true
    deltaScan: true
  bandit:
    enabled: true
    deltaScan: true
  gosec:
    enabled: true
    deltaScan: true
  brakeman:
    enabled: true
    deltaScan: true
```

Only `enabled` and `deltaScan` in this phase. Other fields (`timeout`, `image`, `resources`) are added in later migrations per the spec's migration path.

**Helm template logic** (pseudocode):
```
{{- range $name, $config := .Values.scanners }}
{{- $prefix := printf "HUSKYCI_SCANNER_%s_" (upper $name | replace "-" "_") }}
- name: {{ $prefix }}ENABLED
  value: {{ $config.enabled | quote }}
- name: {{ $prefix }}DELTA_SCAN
  value: {{ $config.deltaScan | quote }}
{{- end }}
```

**Chart.yaml bump:** `version: 0.5.0` and `appVersion: 0.5.0`.

**Also update:** `k8s-infrastructure-live/components/huskyci/next/values.yaml` with same `scanners:` block.

**Verification:** `helm lint` the chart, verify env vars appear in rendered template.

---

## Phase 6: End-to-End Tests

**Hard-block for:** Phase 7 (RAG/skills reflect final state)

**Kanban card:** `phase-6-e2e`

**Files:**
- Create: test script or manual verification steps

**Verification steps:**
1. Build + push API image to ECR
2. Build + push client image to ECR
3. Update k8s-infrastructure-live values.yaml with new image tags
4. Update .github anotaai-sast.yml with new client tag
5. Trigger a PR scan on a test repo
6. Verify scanner pods have `HUSKYCI_DELTA_SCAN=true` env var (check pod spec)
7. Verify delta-capable scanners use `git sparse-checkout` (check pod logs)
8. Verify non-delta scanners still do full clone
9. Verify scan results match expectations

---

## Phase 7: RAG + Skills Update

**Hard-block for:** None (final phase)

**Kanban card:** `phase-7-rag-skills`

**Tasks:**
1. Write RAG doc `platform-knowledge/huskyci-delta-scanning.md` — architecture, Helm config pattern, performance
2. Update `huskyci` skill — add pitfalls for delta scanning (sparse-checkout failure, `%CHANGED_FILES%` empty handling, Helm scanner config pattern)
3. Update `rag-update/.rag/page_catalog.json`
4. Memory cleanup — remove any stale technical entries now captured in RAG

---

## Phase Execution Order (Hard-Blocks)

```
Phase 1 (API Core) ──→ Phase 2 (Scanner Cmds) ──→ Phase 3 (Client) ──→ Phase 4 (Workflow) ──→ Phase 5 (Helm) ──→ Phase 6 (E2E) ──→ Phase 7 (RAG/Skills)
```

Each phase creates a PR in its target repo. Phase 6 is manual verification (no PR). Phase 7 is documentation only.

**Phase 1 PR:** `huskyci-api` (main)
**Phase 2 PR:** same branch as Phase 1 (appended commits)
**Phase 3 PR:** same branch as Phase 1 (appended commits)
**Phase 4 PR:** `.github` repo (master + develop)
**Phase 5 PR:** `k8s-infrastructure-live` (master, unreleased + next tracks)
**Phase 6:** manual, no PR
**Phase 7:** `anotaai-platform-docs` RAG (direct commit)

---

## Orchestrator Notes

- Each phase is a Hermes Kanban card dispatched to a dedicated subagent with full context from this plan and the spec.
- Subagents get the spec doc path and the specific phase instructions.
- After each phase completes, the orchestrator validates: build passes, tests pass, no regressions.
- The orchestrator creates PRs for phases 1-3 (combined into one `huskyci-api` PR), phase 4 (`.github`), phase 5 (`k8s-infrastructure-live`).
- Helm chart version bump: `0.4.0` → `0.5.0` in `Chart.yaml`.
