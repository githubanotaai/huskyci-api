# Gitleaks CI contract fixture

A single file that always matches the built-in `github-pat` rule in [gitleaks](https://github.com/gitleaks/gitleaks) v8+ when run with the default config:

```bash
gitleaks dir /path/to/gitleaks_e2e_fixture -f json
```

This directory is under `testdata/`; repository [.gitleaks.toml](/.gitleaks.toml) allowlists `testdata/` for repo-wide scans, but **CI** mounts only this path into a container as `/scan`, so the allowlist does not apply and the default rules run.

**Do not** put real secrets in this path—use the documented placeholder token pattern.
