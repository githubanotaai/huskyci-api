# Repository Guidelines

## Project Structure & Module Organization

This repository contains three independent Go modules. `api/` is the REST API that orchestrates security scans and Docker/Kubernetes execution. `client/` is the CI-facing command-line client. `cli/` is an interactive tool for target and token management. Tests live beside the code as `*_test.go` files, often with Ginkgo/Gomega suite files. Deployment assets are in `deployments/`; documentation and plans are under `docs/`.

## Build, Test, and Development Commands

- `make build-all`: builds API, client, and CLI binaries.
- `make test`: runs Go tests and coverage for `api/` and `client/`.
- `cd api && go test -race -count=1 ./...`: mirrors CI-style race testing for one module; repeat for `client` and `cli`.
- `cd api && go vet ./...`: runs vet checks; CI runs this per module.
- `cd api && golangci-lint run ./...`: runs module linting; repeat for each module.
- `make compose`: rebuilds and starts `deployments/docker-compose.yml`.

## Coding Style & Naming Conventions

Use idiomatic Go formatting with `gofmt`; Go source uses tabs. Keep package names short, lowercase, and aligned with directory names. Use clear camelCase/PascalCase for new identifiers. Error strings should be lowercase and should not end with punctuation. Each module has its own `.golangci.yml`; suppressed staticcheck style rules (`ST*`) are for legacy compatibility, not a model for new code.

## Testing Guidelines

Prefer focused unit tests next to the package under test. Name files `*_test.go` and test functions `Test...`; use existing Ginkgo/Gomega patterns where already present. Run `go test -race -count=1 ./...` in every affected module before opening a PR. Use `make test` when coverage output is useful.

## Commit & Pull Request Guidelines

Recent history uses concise messages such as `feat: US-001 - ...`, merge commits, and occasional `revert/...` messages. Keep commits scoped and reference the issue or user story when available. PRs should follow `.github/pull_request_template.md`: description, proposed changes, linked issue (`Closes #...`), and exact testing steps. CI must pass, and one approval is required.

## Security & Configuration Tips

Copy `.env.example` to `.env` for local configuration and never commit secrets. Document scanner image, Kubernetes, Docker, and credential changes in `README.md` when behavior or required variables change. Run `bash deployments/scripts/verify-depl-scripts.sh` after changing deployment scripts.
