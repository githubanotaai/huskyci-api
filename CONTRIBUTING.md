# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue or pull request description.

## Development Setup

### Prerequisites

- Go 1.23+
- Docker (for building images)
- [golangci-lint](https://golangci-lint.run/docs/welcome/install/) v2.x (for linting)

### Running tests

```sh
# All modules
cd api && go test -race ./...
cd client && go test -race ./...
cd cli && go test -race ./...

# Lint
cd api && golangci-lint run ./...
cd client && golangci-lint run ./...
cd cli && golangci-lint run ./...
```

### Building images

```sh
docker build --platform linux/amd64 -f deployments/dockerfiles/api.Dockerfile .
docker build --platform linux/amd64 -f deployments/dockerfiles/client.Dockerfile .
```

## Pull Request Process

1. Create a branch from `main`.
2. Ensure all tests pass and lint is clean (`go test -race ./...`, `golangci-lint run ./...`).
3. CI will run automatically on your PR: build, test, lint, and Docker build validation.
4. Update the README if your change affects configuration, environment variables, or output behavior.
5. One approval is required to merge.

## Code Style

- Follow idiomatic Go patterns.
- The project uses `golangci-lint` v2 with a `.golangci.yml` config in each module directory.
- `ST*` (stylecheck) rules are suppressed in the legacy codebase. New code should follow Go conventions.
- Error strings should be lowercase and not end with punctuation (per Go convention).

## Project Structure

```
api/          -- REST API server (creates and monitors scanner pods)
client/       -- CLI client (calls API, prints results, generates SonarQube output)
cli/          -- Interactive CLI for target/token management
deployments/  -- Dockerfiles and deployment scripts
```

Each directory is an independent Go module with its own `go.mod`.

## Code of Conduct

This project follows the [Contributor Covenant v1.4](http://contributor-covenant.org/version/1/4/).
Be respectful, constructive, and professional in all interactions.

Report unacceptable behavior to the repository maintainers via GitHub Issues.
