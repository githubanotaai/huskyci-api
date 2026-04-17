<p align="center">
  <img src="https://raw.githubusercontent.com/wiki/globocom/huskyCI/images/huskyCI-logo.png" align="center" height="" />
</p>

<p align="center">
  <a href="https://github.com/rafaveira3/writing-and-presentations/blob/master/DEFCON-27-APP-SEC-VILLAGE-Rafael-Santos-huskyCI-Finding-security-flaws-in-CI-before-deploying-them.pdf"><img src="https://img.shields.io/badge/DEFCON%2027-AppSec%20Village-black"/></a>
  <a href="https://github.com/rafaveira3/contributions/blob/master/huskyCI-BlackHat-Europe-2019.pdf"><img src="https://img.shields.io/badge/Black%20Hat%20Europe%202019-Arsenal-black"/></a>
  <a href="https://defectdojo.readthedocs.io/en/latest/integrations.html#huskyci-report"><img src="https://img.shields.io/badge/DefectDojo-Compatible-brightgreen"/></a>
</p>

# huskyCI

huskyCI is an open-source tool that orchestrates security tests inside Kubernetes and centralizes results for analysis and metrics.

It performs static security analysis across multiple languages and frameworks:

| Language | Tools |
|----------|-------|
| Python | [Bandit][Bandit], [Safety][Safety] |
| Ruby | [Brakeman][Brakeman] |
| JavaScript | [Npm Audit][NpmAudit], [Yarn Audit][YarnAudit] |
| Go | [Gosec][Gosec] |
| Java | [SpotBugs][SpotBugs] + [Find Sec Bugs][FindSec] |
| HCL | [TFSec][TFSec] |
| Secrets | [GitLeaks][Gitleaks] |

> Forked from [globocom/huskyCI](https://github.com/globocom/huskyCI) and maintained by [@githubanotaai](https://github.com/githubanotaai).

## Architecture

```
GitHub Actions workflow triggers
  |
  v
huskyci-client (runs inside code-analysis runner pod)
  |
  v
huskyci-api (Kubernetes deployment, creates scanner pods)
  |
  v
Scanner pods (enry, bandit, gosec, gitleaks, npmaudit, etc.)
  |
  v
Results collected, returned to client, reported to SonarQube
```

The project has three components, all in this repo:

| Component | Path | Description |
|-----------|------|-------------|
| **API** | `api/` | REST API that receives analysis requests, creates scanner pods in Kubernetes, collects results |
| **Client** | `client/` | CLI binary that runs inside the GitHub Actions runner, calls the API, prints results |
| **CLI** | `cli/` | Interactive CLI for managing targets and tokens (optional) |

## Building

### Binaries

```sh
# API
cd api && go build -o huskyci-api server.go

# Client
cd client/cmd && go build -o huskyci-client main.go

# CLI
cd cli && go build -o huskyci-cli main.go
```

### Docker images

```sh
# API image
docker build --platform linux/amd64 \
  -f deployments/dockerfiles/api.Dockerfile .

# Client image
docker build --platform linux/amd64 \
  -f deployments/dockerfiles/client.Dockerfile .
```

## Configuration

### API environment variables

| Variable | Description |
|----------|-------------|
| `HUSKYCI_DATABASE_DB_ADDR` | Database address |
| `HUSKYCI_DATABASE_DB_NAME` | Database name |
| `HUSKYCI_DATABASE_DB_USERNAME` | Database username |
| `HUSKYCI_DATABASE_DB_PASSWORD` | Database password |
| `HUSKYCI_API_DEFAULT_USERNAME` | Default API user |
| `HUSKYCI_API_DEFAULT_PASSWORD` | Default API password |
| `HUSKYCI_API_ALLOW_ORIGIN_CORS` | CORS origin |
| `HUSKYCI_INFRASTRUCTURE_USE` | `kubernetes` or `docker` |
| `HUSKYCI_KUBERNETES_NAMESPACE` | Namespace for scanner pods |
| `HUSKYCI_KUBERNETES_NODE_SELECTOR` | Node selector for scanner pods (e.g. `karpenter.sh/nodepool=actions-runner`) |
| `HUSKYCI_KUBERNETES_TOLERATIONS` | Tolerations for scanner pods (e.g. `actions-runner=true:NoSchedule`) |
| `HUSKYCI_KUBERNETES_POD_SCHEDULING_TIMEOUT` | Timeout in seconds for pod scheduling (default: 60) |

### Client environment variables

| Variable | Description |
|----------|-------------|
| `HUSKYCI_CLIENT_API_ADDR` | huskyCI API URL |
| `HUSKYCI_CLIENT_REPO_URL` | Repository URL to analyze |
| `HUSKYCI_CLIENT_REPO_BRANCH` | Branch to analyze |
| `HUSKYCI_CLIENT_TOKEN` | API authentication token |

## Output

When vulnerabilities are found, the client prints a summary first, followed by collapsible detail groups (in GitHub Actions):

```
[HUSKYCI][SUMMARY] Total
[HUSKYCI][SUMMARY] High: 4
[HUSKYCI][SUMMARY] Medium: 2
[HUSKYCI][SUMMARY] Low: 3

::group::JavaScript - NpmAudit Details (6 findings)
[HUSKYCI][!] Title: Vulnerable Dependency: express <=4.21.2
[HUSKYCI][!] Severity: high
...
::endgroup::

[HUSKYCI][!] Analysis completed. Blocking vulnerabilities (HIGH/MEDIUM) were found.
[HUSKYCI][!] This is NOT an infrastructure error -- the security scan ran successfully.
[HUSKYCI][!] Fix the vulnerabilities listed above before merging.
```

Exit code `190` means the scan succeeded but HIGH/MEDIUM vulnerabilities were found. This is not an infrastructure error.

## CI

CI runs on every push/PR to `main` using GitHub-hosted runners:

- **Build & Test**: matrix across `api/`, `client/`, `cli/` (Go 1.23, `go vet`, `go test -race`)
- **Lint**: [golangci-lint](https://golangci-lint.run/) v2.11.4
- **Docker Build**: validates both Dockerfiles build (no push)

No secrets required. Runs on any fork.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development process and PR guidelines.

## License

huskyCI is licensed under the [BSD 3-Clause License](LICENSE.md).

[Bandit]: https://github.com/PyCQA/bandit
[Safety]: https://github.com/pyupio/safety
[Brakeman]: https://github.com/presidentbeef/brakeman
[Gosec]: https://github.com/securego/gosec
[NpmAudit]: https://docs.npmjs.com/cli/audit
[YarnAudit]: https://yarnpkg.com/lang/en/docs/cli/audit/
[Gitleaks]: https://github.com/zricethezav/gitleaks
[SpotBugs]: https://spotbugs.github.io
[FindSec]: https://find-sec-bugs.github.io
[TFSec]: https://github.com/liamg/tfsec
