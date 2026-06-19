# Prompt — Implement GitHub issue `#26` in `githubanotaai/huskyci-api`

> **How to use this prompt:** Replace `26` with the issue number
> you are implementing before running. This prompt is reusable across all issues
> created from the gap analysis, performance assessment, and test suite reviews.
>
> **Two ways to run it:**
>
> - **Solo agent (interactive):** paste the substituted prompt into a single
>   Claude/Codex/etc. session and let it work top to bottom.
> - **Tamandua orchestration (recommended for batched issues):** hand the
>   substituted prompt to `tamandua workflow run feature-dev-github-pr` and
>   let the multi-agent pipeline (planner → setup → developer → verifier →
>   tester → pr → reviewer) execute it. See **Appendix A — Operator runbook
>   (Tamandua)** at the end of this file.
>
> The body below is written for the agent doing the work and is identical in
> both modes. The runbook is for the human launching/monitoring the run.

You are an agent with the GitHub CLI (`gh`) and the ability to check out
`githubanotaai/huskyci-api`. Your task is to read, understand, implement,
validate, and submit a change for issue **#26**.

The finish line is a **reviewable pull request**, not a local commit or a
comment on the issue.

---

## Hard rules — read first, these define the safety envelope

**1. The deliverable is a pushed branch + a pull request.**
A local commit that is never pushed is not a deliverable.
Implement → validate → commit → **push** → **open PR**. Only then comment on the issue.

**2. Do not self-certify completion on the public record.**
Do not check acceptance-criteria boxes yourself. In the PR description, state
which criteria you believe are met and the evidence; leave the boxes for
review/merge to tick. The issue comment links the PR and reports status —
it does not declare the issue done.

**3. Never `git add .`.**
Stage explicitly by path, then re-review the *staged* set before committing.
Confirm `.gitignore` excludes test/build artifacts and secrets first.

**4. Do not guess spec-governed behavior.**
For anything `CLAUDE.md` defines — scanner-addition touchpoints, delta-scan
invariants, runtime kill-switches — implement the cited section verbatim.
For anything the gap analysis defines with a confirmed finding number (#1–#17) —
implement what the finding specifies, cite the number in code comments and the PR.
If the issue is silent on or conflicts with either document, **stop and surface it**.
"Document an assumption and proceed" is allowed only for non-semantic choices
(file layout, test naming, formatting). If the issue text conflicts with `CLAUDE.md`
or the gap analysis, **those documents win and you stop** rather than implementing
either reading.

**5. Confirm #26 is actually implementable before doing anything.**
Stop if the issue does not exist, is closed, or is a tracking/epic issue
(a meta-issue listing other work is not a code task).

**6. Spec documents must be present.**
If `CLAUDE.md` is not in the repo, stop and report. If the issue references a
gap analysis finding that is not documented in the repo, stop and report.

**7. Stay in scope.**
Implement only what #26 requires. No unrelated improvements,
no architecture rewrites, no speculative additions. The confirmed bugs (#2, #7, #8)
and the behavioral contracts below must not be worsened by any change,
even incidentally.

**8. Output contract — make the deliverable machine-readable.**
The final line of your successful run MUST be exactly:

```
STATUS: done
```

Immediately preceded (within the last ~20 lines) by a line of the form:

```
PR: https://github.com/githubanotaai/huskyci-api/pull/<N>
```

On failure, the final line MUST be exactly `STATUS: failed` followed by a
`REASON:` line. These markers are parsed by orchestrators (Tamandua's
`pr` and `review` steps; CI scripts) — emitting a prose summary like
"Done!" instead breaks the contract and triggers retries even when the
work succeeded. Tamandua's `pr` step expects `PR:\s*https?://github\.com/[^/]+/[^/]+/pull/\d+`; the
`review` step expects the `STATUS: done` literal.

If `gh` is not authenticated, **stop** and tell the operator to run
`gh auth login` (and `gh auth refresh -s repo` if needed), then re-run.

---

## Behavioral contracts — must not be broken by any change

These are confirmed strengths documented in the gap analysis.
Any change that weakens them is out of scope for any individual issue.

| Contract | Location | Rule |
|----------|----------|------|
| Exit code 190 | `client/` | Client exits `190` when blocking vulnerabilities found. This is a load-bearing CI/CD signal consumed by GitHub Actions. The value must not change. |
| Cross-repo token rejection | `api/token/token.go:120` | A token bound to repo A must be rejected for repo B. Must not be weakened. |
| Input validation — allowlist | `api/util/util.go:169-219` | All three validators (`CheckMaliciousRepoURL`, `CheckMaliciousBranch`, `CheckMaliciousChangedFiles`) reject by default. Must remain allowlist-based, not denylist-based. |
| Shell injection prevention | `api/config.yaml` | Scanner `cmd` templates use `strings.ReplaceAll`, not `fmt.Sprintf`. Placeholders (`%GIT_REPO%`, `%GIT_BRANCH%`) are double-quoted. Must not regress to format-string substitution. |
| K8s timeout enforcement | `api/kubernetes/api.go::WaitPod` | Timeout via `ListOptions.TimeoutSeconds` must continue to work. |
| Race detector | CI | `go test -race -count=1 ./...` must pass on every module. New code must not introduce data races. |
| Per-module independence | `api/`, `client/`, `cli/` | Each module has its own `go.mod`. A change in `api/` must not require modifying `client/go.mod` or `cli/go.mod`. |

**Confirmed bugs that must not be worsened:**

| Bug | Location | Risk |
|-----|----------|------|
| #8 Finalization order | `api/securitytest/run.go:63-83` | `setFinalResult` (line 81) is clobbered by `defer setToAnalysis` (line 65). Any change near this code must not make the clobber worse or add new dependence on the broken ordering. |
| #2 Docker timeout no-op | `api/dockers/api.go:99-116` | `WaitContainer` ignores its `timeOutInSeconds` parameter. Changes to the timeout path must not remove the parameter or rename it in a way that makes the no-op harder to find and fix. |
| #7 No panic recovery | `api/securitytest/run.go:100-124, 149-181` | Scanner goroutines have no `defer recover()`. Changes that add new `g.Go` calls must not omit panic recovery. |

---

## Step 1 — Prepare the workspace and confirm write access

```bash
pwd
gh auth status
```

If not already inside the repo:

```bash
gh repo clone githubanotaai/huskyci-api
cd huskyci-api
```

Check state and permissions:

```bash
gh repo view githubanotaai/huskyci-api \
  --json name,defaultBranchRef,hasIssuesEnabled,viewerPermission
git status
git rev-parse HEAD
```

**Stop if `viewerPermission` is `READ` or `NONE`.** Tell the operator to grant
write access — otherwise all the work fails at push time.

Branch from the up-to-date default branch. The branch name MUST contain
`issue-26` so it is traceable, but a descriptive suffix is
encouraged (e.g. `issue-26-perf-concurrency-benchmarks`).
Record the name you picked once and reuse it through Steps 9–11.

```bash
git fetch origin
DEFAULT=$(gh repo view githubanotaai/huskyci-api \
  --json defaultBranchRef --jq '.defaultBranchRef.name')

BRANCH="issue-26-<short-slug>"   # e.g. issue-61-perf-concurrency-benchmarks
git checkout "$BRANCH" 2>/dev/null || \
  git checkout -b "$BRANCH" "origin/$DEFAULT"
```

---

## Step 2 — Confirm #26 is actionable

```bash
gh issue view 26 \
  --repo githubanotaai/huskyci-api \
  --comments
```

**Stop and report if the issue:**
- does not exist
- is already closed
- is a tracking or epic issue (title contains "Track", "Epic", or "Backlog";
  body is a checklist of other issues with no implementation requirements of its own)
- has no acceptance criteria and no clearly required behavior
- declares `Depends on #X` for an issue that is still open (note the open
  dependencies in your final report; do not implement around them)

Do not infer requirements from the title alone. Read the full body, all comments,
any linked files, and every acceptance criterion. Extract and record:

- Problem statement (what is currently wrong or missing)
- Required behavior (what the implementation must do)
- Acceptance criteria (what must be true for the issue to be closeable)
- Which module(s) are affected (`api/`, `client/`, and/or `cli/`)
- Which gap analysis finding(s) this issue implements (e.g. "implements gap #3")
- Files likely touched
- Tests that must exist after the change
- Risks or unclear points that need surfacing before implementation
- Any `Depends on #X` lines and whether those deps are open or merged

---

## Step 3 — Locate and confirm the spec documents

```bash
# Primary spec document
cat CLAUDE.md

# Confirm gap analysis findings are documented
grep -r "gap #\|finding #\|Gap #" . \
  --include="*.md" -l 2>/dev/null

# Identify which finding this issue implements
# (extract from issue body — look for "#N" references)
```

Record:
- The current commit SHA at which `CLAUDE.md` was read
- The gap analysis finding number(s) this issue implements
- The specific section of `CLAUDE.md` that governs the required behavior (if any)

**Stop if `CLAUDE.md` is not present.** Report: "CLAUDE.md not found; commit it
or provide it, then re-run."

**Stop if the issue references a gap finding that is not documented anywhere in
the repo.** Do not implement against the conversation that created the issue.

---

## Step 4 — Inspect the affected module(s)

The stack is Go. There are three independent modules. Determine which this issue touches:

```bash
# Confirm module boundaries
cat api/go.mod | head -5
cat client/go.mod | head -5
cat cli/go.mod | head -5

# Find files likely relevant to the issue
# (replace <keywords> with terms from the issue body)
grep -r "<keywords>" api/ client/ cli/ \
  --include="*.go" -l 2>/dev/null

# Check existing tests in the affected area
find <affected-module>/ -name "*_test.go" | sort

# Check linter config for the affected module
cat <affected-module>/.golangci.yml

# Check CI workflow
cat .github/workflows/ci.yaml
```

Read the source files you will modify **before** writing any code.
Do not assume function signatures, struct field names, or package names.

**If this issue involves adding or modifying a scanner**, read `CLAUDE.md`'s
scanner-addition checklist. The checklist identifies all touchpoints that must
be updated together. Missing any one of them is a confirmed source of drift
(documented in `CLAUDE.md` explicitly). Record each touchpoint and confirm
the issue covers them all, or surface the gap.

**If this issue involves `api/securitytest/run.go`**, re-read the confirmed
bug #8 description in the hard rules above before touching that file.

---

## Step 5 — Capture the baseline before any change

Run the test and lint commands for each affected module and record pass/fail.
This is the reference for Step 8 — without it you cannot tell whether a later
failure is yours or pre-existing.

**Do not edit any code until the baseline is recorded.**

For each affected module (`api/`, `client/`, `cli/`):

```bash
cd <module>

# Format check
gofmt -l .

# Vet
go vet ./...

# Lint (each module has its own config)
golangci-lint run ./...

# Tests with race detector (required by CI)
go test -race -count=1 ./...

# If the module has a Makefile
make help  # list available targets
```

Record each command's exit code and any failures. Pre-existing failures must
be documented and must not be silently fixed or silently inherited.

---

## Step 6 — Write the implementation plan before touching code

Write:

1. **What changes:** the minimal set of modifications required by the issue
2. **Files touched:** list every file that will be created or modified
3. **Module(s) affected:** which of `api/`, `client/`, `cli/`
4. **Spec reference:** which section of `CLAUDE.md` or which gap finding (#N) governs each behavior
5. **Tests to add:** what test cases will be added, what behavior each covers,
   and whether any require `//go:build integration`
6. **Fixtures required:** if the issue touches a scanner parser, list the
   `testdata/` fixture files needed (clean output, finding output, malformed output)
7. **Behavioral contracts checked:** confirm each contract in the table above
   is unaffected, or explain why a contract must change and get confirmation

Apply hard rule 4: for anything `CLAUDE.md` or the gap analysis specifies,
the plan cites the section/finding and implements it verbatim. If the issue
is ambiguous or conflicts with either document, **stop here and surface it**
instead of planning a guess.

Assumptions are allowed only for non-semantic choices: file layout, test
function naming, log message wording.

---

## Step 7 — Implement only what #26 requires

Follow the existing project style. Read the file before editing it.
Prefer simple, readable code over clever code.

**Go-specific requirements (all modules):**

- `t.Helper()` in every test assertion helper
- `t.Parallel()` in every test that does not share mutable state
- `t.Setenv` (not `os.Setenv`) for environment variable tests
- Never call `os.Exit` in a test — test the function that decides the exit code
- `//go:build integration` on any test that requires Docker, Kubernetes,
  or a real MongoDB instance
- Standard library only unless the module's `go.mod` already imports the package
- No new `go.mod` dependencies unless the issue explicitly requires one and
  you name it and justify it in the PR

**If this issue touches a scanner parser:**

- Add `testdata/<scanner>/` fixtures: `high_vuln.json`, `no_vuln.json`,
  `malformed.json`
- Use the JSON schema from the actual tool's output — do not invent field names
- `wizcli_test.go` is the style reference for parser tests
- The malformed fixture must test that the parser returns an error rather than
  panicking (gap #7 — parsers must not panic on bad input)

**If this issue touches `api/securitytest/run.go`:**

- Do not add new `g.Go(...)` calls without a `defer func() { if r := recover() ... }()`
  wrapper (gap #7)
- Do not add new `defer` calls inside `Start()` that reorder relative to
  `setFinalResult` (bug #8)
- Use the existing `mockRunner` interface (`api/securitytest/runner.go`) for
  any new orchestration tests — do not write a parallel mock

**If this issue touches `api/util/util.go` validators:**

- The validators must remain allowlist-based (behavioral contract)
- Add table-driven tests with both "must block" and "must allow" rows
- SSRF gap cases (RFC1918, link-local, loopback) that are not yet blocked
  must be placed in a skipped subtest with:
  `t.Skip("Gap #10 — remove when CheckMaliciousRepoURL blocks RFC1918")`

**If this issue touches the client exit code:**

- Exit code 190 is a behavioral contract — do not change the value
- The function that decides the exit code must be separately testable
  (not embedded in `main()`)

**Skip discipline for tests that document unfixed bugs:**

```go
// Correct form — asserts DESIRED behavior, fails today, skip until fix:
func TestFoo_DesiredBehavior(t *testing.T) {
    t.Skip("Bug #N — remove after [specific function] is fixed in [file]")
    // assertion body expresses what correct behavior looks like
}

// Correct form — gap subtest, parent stays green:
t.Run("gap_N_description", func(t *testing.T) {
    t.Skip("Gap #N — remove after [specific fix] is implemented")
})
```

Never skip to hide a flaky test. Only skip when production code is known
wrong and the test documents what "fixed" looks like.

---

## Step 8 — Validate against the baseline

Run the same commands from Step 5 for each affected module. Compare results:

- **Failures your change introduced** → fix before proceeding
- **Failures present in the baseline** → document as pre-existing;
  do not silently fix or silently inherit them

Additionally, confirm:

```bash
# Confirm no files were accidentally staged from outside the affected module
git status

# Confirm race detector passes
go test -race -count=1 ./...

# Confirm vet passes
go vet ./...

# Confirm the specific tests added for this issue pass (or are correctly skipped)
go test -race -count=1 -run "TestFunctionName" ./path/to/package/...
```

Tie completion to the specific tests that cover the issue's acceptance criteria
passing (or being correctly skipped with documented reasons) — not merely a
green overall suite.

---

## Step 9 — Review the diff and stage explicitly

```bash
git status
git diff
```

Before staging, confirm:

- `.gitignore` covers test/build artifacts (`*.test`, `coverage.out`,
  `vendor/`, build outputs) and secrets (`.env`, `*.pem`, `*_key`)
- No files outside the issue's scope are modified
- No generated files (`vendor/`, module caches) are included
- No secrets or credentials are present in any staged file
- New test files cover the issue's acceptance criteria
- `CLAUDE.md` is updated if the issue changes any documented behavior,
  scanner checklist, or architectural invariant

Stage by path, never by glob:

```bash
git add api/securitytest/gosec.go
git add api/securitytest/gosec_test.go
git add api/securitytest/testdata/gosec/high_vuln.json
# ... one path at a time
```

Re-review the staged set:

```bash
git diff --cached
```

Confirm the staged diff matches the implementation plan from Step 6 exactly —
nothing more, nothing less.

---

## Step 10 — Commit, push, open the PR

Write a commit message that describes the actual change, not the issue number:

```bash
git commit -m "<imperative summary of the actual change>

Implements gap #N: <one-line description of the finding>
Ref: CLAUDE.md §<section> (if applicable)

Files changed:
- <file>: <what changed>
- <file>: <what changed>

Tests added:
- <TestFunctionName>: <what it covers>"

git push -u origin "$BRANCH"
```

Open the PR (idempotent — if a PR already exists for this branch, update it
rather than creating a second one):

```bash
# Check for existing PR first
gh pr list --repo githubanotaai/huskyci-api --head "$BRANCH"

# Create only if none exists, and CAPTURE THE URL
PR_URL=$(gh pr create \
  --repo githubanotaai/huskyci-api \
  --title "<imperative summary matching the commit>" \
  --body "$(cat <<'PRBODY'
## Summary

<What changed and why — 2-3 sentences>

## Gap analysis reference

Implements gap #N: <finding title>
CLAUDE.md reference: <section, if applicable>

## Files changed

- `<file>`: <what changed>

## Tests added

| Test | What it covers | Status |
|------|---------------|--------|
| `TestFoo` | <behavior> | Passes |
| `TestBar_DesiredBehavior` | <behavior — known bug, skipped> | Skipped: Bug #N |

## Validation

Commands run against baseline (Step 5) and post-change (Step 8):

\`\`\`
go vet ./...              baseline: pass  post-change: pass
golangci-lint run ./...   baseline: pass  post-change: pass
go test -race -count=1 ./... baseline: N passed  post-change: N passed
\`\`\`

Pre-existing failures (if any): <list or "none">

## Behavioral contracts verified

- [ ] Exit code 190 unchanged
- [ ] Cross-repo token rejection unaffected
- [ ] Input validators remain allowlist-based
- [ ] Shell injection prevention unaffected
- [ ] `go test -race` passes
- [ ] Per-module `go.mod` independence preserved

## Acceptance criteria

<List each criterion from the issue and the evidence that it is met.>
<Do not tick the issue's checkboxes — leave that to review/merge.>

Closes #26
PRBODY
)")

# Emit the PR URL on its own line — Tamandua's `pr` step regex matches this:
echo "PR: $PR_URL"
```

If a PR already existed, recover its URL with:

```bash
PR_URL=$(gh pr list --repo githubanotaai/huskyci-api \
  --head "$BRANCH" --json url --jq '.[0].url')
echo "PR: $PR_URL"
```

---

## Step 11 — Comment on the issue and verify

Post a single comment on #26 with the PR link and a one-line status.
Do not check the issue's acceptance-criteria boxes.
If you have already commented on a prior run, update or reply to the existing
comment rather than posting a duplicate.

```bash
gh issue comment 26 \
  --repo githubanotaai/huskyci-api \
  --body "Implementation submitted for review: $PR_URL

Status: PR open, validation passed against baseline. Acceptance criteria
assessment is in the PR description — leaving checkbox confirmation to review."

# Verify the comment landed and the PR is actually visible to GitHub:
gh issue view 26 --repo githubanotaai/huskyci-api \
  --comments --json comments --jq '.comments[-1].body' | head -5
gh pr view "$PR_URL" --json state,headRefName,headRefOid \
  | tee /tmp/pr-verify.json
```

If `gh pr view` cannot find the PR, the push or PR creation silently failed —
**emit `STATUS: failed` with a `REASON:` line and stop** rather than reporting
success.

---

## Step 12 — Final report

Print your structured report, then end with the **machine-readable closing
block** the output contract requires (hard rule #8):

1. **Issue summary** — problem statement, required behavior, acceptance criteria,
   and confirmation it was actionable (not tracking/epic, not closed)
2. **Spec references** — `CLAUDE.md` sections and gap finding numbers cited
3. **Implementation summary** — what changed and why
4. **Files changed** — full list
5. **Tests added** — test names, what each covers, and whether any are correctly
   skipped with a documented reason
6. **Validation results** — commands run, baseline vs. post-change comparison,
   any pre-existing failures documented
7. **Behavioral contracts** — confirmation each contract is unaffected,
   or documented explanation of any intentional change
8. **Assumptions** — non-semantic only; any spec-vs-issue conflicts surfaced
9. **Remaining gaps** — anything the issue requires that could not be implemented,
   with reason
10. **PR URL** and the issue-comment status
11. **Commit hash** and branch (pushed, confirmed)

Closing block — MUST be the last lines of your output, exactly:

```
PR: <full https URL of the opened PR>
BRANCH: <branch name pushed to origin>
COMMIT: <head SHA pushed>
STATUS: done
```

On failure, replace the closing block with:

```
REASON: <one-line root cause>
STATUS: failed
```

Do not claim #26 is complete.
State which acceptance criteria are implemented and validated with evidence,
and leave the completion judgment to review and merge.

---

# Appendix A — Operator runbook (Tamandua)

Use this when launching the prompt through Tamandua's
`feature-dev-github-pr` workflow. Skip if you're running the prompt in a
single interactive session.

## A.1 Pre-flight

```bash
# Confirm Tamandua is healthy and no stale run will collide
tamandua status

# Bring up the dashboard so you can watch progress live
tamandua dashboard start
open -a "Google Chrome" http://localhost:3334

# Confirm gh is authed in the target checkout — Tamandua's `pr` step needs it
cd /path/to/huskyci-api
gh auth status

# Confirm the issue is open and actionable before spending tokens
gh issue view 26 --repo githubanotaai/huskyci-api
```

## A.2 Launch the run

Substitute `26` (and only that placeholder) in this file, then
hand the full body to Tamandua as the task. Pin the working directory to the
huskyci-api checkout so all agents share the same view.

```bash
TASK="$(sed 's/26/<N>/g' /path/to/huskyci-api/prompt.md)"

cd /path/to/huskyci-api
tamandua workflow run feature-dev-github-pr "$TASK" \
  --working-directory-for-harness "$(pwd)"
# -> Run: <RUN-ID>
```

Capture the `RUN-ID` printed by the launch command — every monitoring command
below takes it.

## A.3 Monitor on a 5-minute cycle

Each tick:

```bash
tamandua status
tamandua logs <RUN-ID> | tail -10
tamandua step stories <RUN-ID>
```

Report a single line: `<RUN-ID>: <state> — done X / running Y / pending Z`.

**Escalation rules (do not violate):**

- **Never cancel, pause, or stop the run.** A pipeline retry is not a
  failure — Tamandua's `pr` step retries on missing `PR:` URL, and the
  `review` step retries on missing `STATUS: done`. Both are recoverable.
- **Never implement code yourself.** If you spot a bug in agent output,
  report it; do not fix it. Let the next agent or a human take it.
- **Never spawn a new workflow unless the user asks.**
- **If `tamandua status` shows the run as `failed`:** run
  `tamandua workflow resume <RUN-ID>`.
- **If `step stories` shows no progress for 10+ minutes:** run
  `tamandua nudge` to wake the schedulers without restarting work.

## A.4 Termination and verification

When `tamandua status` shows the run as `completed`:

```bash
# Tamandua used whatever BRANCH the agent chose in Step 1 — it may not
# match a fixed naming scheme. Search by issue number:
gh pr list --repo githubanotaai/huskyci-api --state all \
  --search "issue-26 in:head" \
  --json number,url,state,title,headRefName,headRefOid

# Confirm the agent's closing block matches reality:
tamandua workflow status <RUN-ID> | tail -20    # look for STATUS: done

# Stop the polling loop (CronDelete the monitoring job)
# Leave the dashboard running unless you want to free port 3334.
```

Things worth eyeballing on the PR before merging (the agent is forbidden
from self-certifying — verification is your job):

- The PR description contains the behavioral-contracts checklist and the
  baseline-vs-post-change validation matrix.
- The issue has a single new comment linking the PR (no duplicates).
- The branch name contains `issue-26` (slug suffix is fine).
- The closing-block `COMMIT` SHA matches `gh pr view <URL> --json headRefOid`.

## A.5 Known retry patterns (informational — do not act on these)

The `feature-dev-github-pr` pipeline has two output-contract gates that
retry on first attempt with high frequency. They are not failures:

| Step | What it expects | Common first-attempt miss |
|------|-----------------|---------------------------|
| `pr` | `PR:\s*https?://github\.com/[^/]+/[^/]+/pull/\d+` | Agent prints "Opened PR <URL>" instead of `PR: <URL>` |
| `review` | Literal `STATUS: done` as last line | Agent prints "Done." or trailing prose |

The hard rule #8 closing block prevents both. If you see more than one
retry on either step, that's worth surfacing — it means the agent is
ignoring the output contract.
