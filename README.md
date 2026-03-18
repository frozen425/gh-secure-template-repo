# gh-secure

A CLI tool for assessing and enforcing GitHub repository security best practices. Scans repository settings, branch protection rules, and security features, then optionally applies remediation to bring them in line with security standards.

## Features

- **13 security checks** covering branch protection, code review policies, secret scanning, and more
- **Assess mode** — audit a repo's security posture with a structured report
- **Apply mode** — automatically remediate failing checks
- **OAuth Device Flow** — interactive browser-based authentication
- **Token capability detection** — pre-flight check of token scopes and plan
- **Configurable thresholds** — tune reviewer counts, required CI checks, and code owner requirements

## Quick Start

### Prerequisites

- Go 1.23 or later

### Build

```bash
make build    # outputs to bin/gh-secure
```

### Authentication

Choose one of the following:

**Option 1: OAuth Device Flow (recommended)**

Register a [GitHub OAuth App](https://github.com/settings/developers) with "Enable Device Flow" checked, then:

```bash
./bin/gh-secure --login --client-id <YOUR_CLIENT_ID>
# Opens browser → enter the displayed code → authorize
# Token is cached to ~/.config/gh-secure/token.json
```

**Option 2: Environment variable**

```bash
export GITHUB_TOKEN=$(gh auth token)
# or
export GITHUB_TOKEN=ghp_your_personal_access_token
```

Required token scopes: `repo`, `read:org`

### Run an Assessment

```bash
./bin/gh-secure --owner <owner> --name <repo>
```

### Apply Remediation

```bash
./bin/gh-secure --owner <owner> --name <repo> --apply

# Skip the 5-second safety delay
./bin/gh-secure --owner <owner> --name <repo> --apply --force
```

## Security Checks

| Severity | Check | Description |
|---|---|---|
| CRITICAL | `branch_protection` | Default branch has protection rules enabled |
| CRITICAL | `require_pr_reviews` | PRs require approving reviews before merge |
| CRITICAL | `vulnerability_alerts` | Dependabot vulnerability alerts enabled |
| CRITICAL | `secret_scanning` | Secret scanning detects leaked credentials ¹ |
| CRITICAL | `secret_scanning_push_protection` | Push protection blocks commits with secrets ¹ |
| HIGH | `dismiss_stale_reviews` | Stale reviews dismissed on new commits |
| HIGH | `require_status_checks` | CI status checks must pass before merge |
| HIGH | `enforce_admins` | Branch protection applies to admins |
| HIGH | `force_push_protection` | Force pushes blocked on default branch |
| HIGH | `branch_deletion_protection` | Default branch protected from deletion |
| MEDIUM | `signed_commits` | Commits must be GPG-signed |
| MEDIUM | `private_vulnerability_reporting` | Researchers can report vulnerabilities privately ¹ |
| LOW | `delete_branch_on_merge` | Head branches auto-deleted after merge |

¹ Requires public repo or GitHub Advanced Security for private repos.

## Configuration Flags

### Check Parameters

| Flag | Default | Description |
|---|---|---|
| `--min-reviewers` | `1` | Minimum required approving reviewers |
| `--required-checks` | none | Comma-separated CI check contexts (e.g. `ci/build,lint`) |
| `--require-codeowners` | `false` | Require code owner reviews |

### Authentication

| Flag | Description |
|---|---|
| `--login` | Authenticate via OAuth device flow |
| `--logout` | Clear cached token |
| `--revoke` | Clear local cache and open GitHub settings to revoke server-side |
| `--client-id` | GitHub OAuth App client ID (required for `--login`) |

### Modes

| Flag | Description |
|---|---|
| `--assess` | Run security assessment (default) |
| `--apply` | Remediate failing checks |
| `--force` | Skip the 5-second safety delay for `--apply` |
| `--debug` | Enable debug logging |
| `--dry-run` | Legacy debug output |

## Auth Precedence

The tool resolves authentication in this order:

1. `--login` — interactive OAuth device flow (caches token)
2. `GITHUB_TOKEN` environment variable
3. Cached token from `~/.config/gh-secure/token.json`

## Example Output

```
[INFO] Token authenticated as: frozen425
[INFO] Auth source: GITHUB_TOKEN env
[INFO] Plan: unknown
[INFO] Token type: classic PAT
[INFO] Scopes: gist, read:org, repo, workflow
[INFO] Assessing security posture for heelerai/skully-poc ...

[INFO] SEVERITY  CHECK                                STATUS    DETAIL
[INFO] --------  -----                                ------    ------
[INFO] CRITICAL  branch_protection                    PASS      enabled
[INFO] MEDIUM    signed_commits                       PASS      enabled
[INFO] CRITICAL  require_pr_reviews                   PASS      enabled
[INFO] HIGH      dismiss_stale_reviews                PASS      enabled
[INFO] HIGH      require_status_checks                PASS      enabled
[INFO] HIGH      enforce_admins                       PASS      enabled
[INFO] HIGH      force_push_protection                PASS      enabled
[INFO] HIGH      branch_deletion_protection           PASS      enabled
[INFO] LOW       delete_branch_on_merge               PASS      enabled
[INFO] CRITICAL  vulnerability_alerts                 PASS      enabled
[INFO] CRITICAL  secret_scanning                      SKIP      requires public repo or GHAS
[INFO] CRITICAL  secret_scanning_push_protection      SKIP      requires public repo or GHAS
[INFO] MEDIUM    private_vulnerability_reporting      SKIP      requires public repo or GHAS

[INFO] Summary: 10 passed, 0 failed, 3 skipped, 0 errors  (total: 13)
[INFO] All checks passing.
```

## Makefile Targets

```bash
make build    # Compile to bin/gh-secure
make test     # Run tests
make vet      # Run go vet
make lint     # Vet + build
make clean    # Remove bin/
make help     # Show all targets
```

## Authors

- frozen425

## License

This project is licensed under the Apache License — see the [LICENSE](LICENSE) file for details.
