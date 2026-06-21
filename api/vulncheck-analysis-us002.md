# US-002: GO-2026-4887 Exploitability Analysis

**Date:** 2026-06-19
**Vulnerability:** GO-2026-4887 — Moby AuthZ plugin bypass when provided oversized request bodies
**Module:** github.com/docker/docker@v23.0.6+incompatible
**Status:** NOT exploitable in huskyci-api

---

## 1. Docker Client Method Enumeration (api/dockers/api.go)

All Docker client operations used by huskyci-api are standard container lifecycle
and image management calls. None involve Docker AuthZ plugin configuration.

| # | Method | Location | Purpose | AuthZ Involvement |
|---|--------|----------|---------|-------------------|
| 1 | `ContainerCreate` | api.go:81 | Create scanner container from image | None — standard container create |
| 2 | `ContainerStart` | api.go:97 | Start a created container | None |
| 3 | `ContainerWait` | api.go:108 | Wait for container to finish executing | None |
| 4 | `ContainerStop` | api.go:129 | Stop a running container | None |
| 5 | `ContainerRemove` | api.go:139 | Remove a stopped container | None |
| 6 | `ContainerList` | api.go:157 | List stopped containers for cleanup | None |
| 7 | `ContainerLogs` | api.go:202 | Read container STDOUT | None |
| 8 | `ContainerLogs` | api.go:216 | Read container STDERR | None |
| 9 | `ImagePull` | api.go:233 | Pull scanner images | None |
| 10 | `ImageList` | api.go:243,259 | Check image availability / list images | None |
| 11 | `ImageRemove` | api.go:265 | Remove images | None |
| 12 | `Ping` | api.go:277 | Health check Docker daemon connectivity | None |

All calls use `goContext.Background()` — no custom headers, no AuthZ token
injection, no plugin configuration.

## 2. Docker Client Initialization

```go
// api/dockers/api.go:67
client, err := client.NewClientWithOpts(client.FromEnv)
```

`client.NewClientWithOpts(client.FromEnv)` creates a Docker client from
environment variables only (`DOCKER_HOST`, `DOCKER_CERT_PATH`,
`DOCKER_TLS_VERIFY`). The following options are configured:

- **DOCKER_HOST**: Docker daemon socket or TCP address
- **DOCKER_CERT_PATH**: TLS certificate directory
- **DOCKER_TLS_VERIFY**: TLS verification flag

**No AuthZ plugin configuration option is set.** The Docker client SDK's
`FromEnv` initializer does not read or configure AuthZ plugins. AuthZ plugins
are a Docker *daemon* feature configured via the daemon's `--authorization-plugin`
flag — not via the client SDK.

## 3. Authorization Imports Check

**No authorization-related imports from `github.com/docker/docker` exist
anywhere in the `api/` module.**

All Docker imports in api/ are:
- `github.com/docker/docker/api/types` — standard type definitions
- `github.com/docker/docker/api/types/container` — container config types
- `github.com/docker/docker/api/types/filters` — list filter utilities
- `github.com/docker/docker/client` — Docker client SDK

The `errdefs.IsUnauthorized` trace in the govulncheck output refers to an
internal HTTP error helper used by the `ImagePull` method to check for HTTP 401
responses. This is standard HTTP status handling, not AuthZ plugin integration.

The `api/token/tokenvalidator.go` file contains `HasAuthorization()` — this is
for huskyci-api's own token-based access control, unrelated to Docker AuthZ.

## 4. Kubernetes Code Path Analysis (api/kubernetes/api.go)

The kubernetes module uses `k8s.io/client-go` exclusively. It does **not**
import or call any Docker client code directly. The govulncheck trace showing
`rest.Request.Stream → client.CheckRedirect` is a transitive dependency path:
k8s client-go internally depends on some shared HTTP utilities from the Docker
client library. `CheckRedirect` is a generic HTTP redirect handler, not an
AuthZ plugin function.

## 5. Conclusion

**The GO-2026-4887 AuthZ plugin bypass vulnerability is NOT exploitable in
huskyci-api.**

Rationale:
1. The vulnerability requires a Docker daemon configured with an AuthZ plugin
   (via `--authorization-plugin` flag). huskyci-api does not configure,
   enable, or interact with Docker AuthZ plugins.
2. huskyci-api uses the Docker client SDK exclusively for standard container
   lifecycle operations (create, start, wait, stop, remove, logs) and image
   management (pull, list, remove).
3. No Docker AuthZ-related imports, API calls, or configuration options are
   present in the entire `api/` module.
4. The Docker client is initialized via `client.FromEnv` which only reads
   host, TLS, and API version settings — no AuthZ plugin configuration is
   possible through this path.
5. This is a **false positive** for this project's usage pattern. The
   vulnerability exists in the dependency code but the vulnerable code path
   is unreachable from huskyci-api.
