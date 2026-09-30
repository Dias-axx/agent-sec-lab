# agentsec report — github / example-org

> **SYNTHETIC EXAMPLE** — generated from test fixtures, not from a real environment.

| Field | Value |
|---|---|
| Tool version | 0.1.0 |
| Data source | replay:org_scenario.json (synthetic) |
| Repository scope | all visible repositories |
| Catalog | `controls/catalog.yaml` (sha256 `d726cee30dc5…`) |
| Started (UTC) | 2026-09-30T06:47:08.582772+00:00 |
| Finished (UTC) | 2026-09-30T06:47:08.589508+00:00 |

## Summary

| PASS | FAIL | ERROR |
|---|---|---|
| 2 | 7 | 0 |

| Control | Title | Severity | SOC 2 | ISO 27001 | Status |
|---|---|---|---|---|---|
| CM-01 | Branch protection with required reviews on default branch | high | CC6.1, CC8.1 | A.8.4, A.8.32 | **FAIL** |
| AC-01 | Two-factor authentication required for organisation members | critical | CC6.1 | A.5.17, A.8.5 | **PASS** |
| DP-01 | Secret scanning and push protection enabled | high | CC6.1, CC7.1 | A.5.17, A.8.12 | **FAIL** |
| VM-01 | Dependabot vulnerability alerts enabled | medium | CC7.1 | A.8.8 | **FAIL** |
| AC-02 | No public repositories unless allowlisted | high | CC6.1, C1.1 | A.5.15, A.8.4 | **FAIL** |
| SC-01 | GitHub Actions references pinned to full commit SHAs | medium | CC8.1, CC9.2 | A.5.21, A.8.28 | **FAIL** |
| AC-03 | Default GITHUB_TOKEN permissions are read-only | high | CC6.1, CC6.3 | A.8.2, A.8.9 | **FAIL** |
| CM-02 | CODEOWNERS file present and valid | low | CC8.1 | A.8.32 | **FAIL** |
| AC-04 | Organisation owner count within threshold | medium | CC6.2, CC6.3 | A.5.18, A.8.2 | **PASS** |

## Details

### CM-01 — Branch protection with required reviews on default branch: FAIL

Check: `github.branch_protection_enabled` · params: `{'required_reviews': 1, 'allow_bypass': False}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | branch 'main': 1 required review(s), need >= 1 |
| example-org/bad-repo | FAIL | branch 'main': 0 required review(s), need >= 1 |

**Remediation:** Protect the default branch (classic protection or a ruleset), require at least the configured number of approving pull-request reviews, and do not let admins bypass it (classic: "Do not allow bypassing" / enforce_admins; rulesets: empty bypass list).

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /repos/example-org/good-repo/branches/main/protection` · 2026-09-30T06:47:08.583776+00:00 · `{'required_approving_review_count': 1, 'enforce_admins': True}`
- `example-org/good-repo` · `GET /repos/example-org/good-repo/rules/branches/main` · 2026-09-30T06:47:08.584040+00:00 · `{'pull_request_required_reviews': 0}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/branches/main/protection` · 2026-09-30T06:47:08.584273+00:00 · `{'status': 404, 'message': 'Branch not protected'}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/rules/branches/main` · 2026-09-30T06:47:08.584465+00:00 · `{'pull_request_required_reviews': 0}`

</details>

### AC-01 — Two-factor authentication required for organisation members: PASS

Check: `github.org_mfa_required` · params: `{}`

| Subject | Status | Detail |
|---|---|---|
| example-org | PASS | 2FA requirement enabled: True |


<details><summary>Evidence</summary>

- `example-org` · `GET /orgs/example-org` · 2026-09-30T06:47:08.584679+00:00 · `{'two_factor_requirement_enabled': True}`

</details>

### DP-01 — Secret scanning and push protection enabled: FAIL

Check: `github.secret_scanning_enabled` · params: `{'require_push_protection': True}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | secret_scanning=enabled, push_protection=enabled |
| example-org/bad-repo | FAIL | secret_scanning=enabled, push_protection=disabled |

**Remediation:** Enable secret scanning and push protection for every repository.

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /repos/example-org/good-repo` · 2026-09-30T06:47:08.584913+00:00 · `{'secret_scanning': 'enabled', 'push_protection': 'enabled'}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo` · 2026-09-30T06:47:08.585166+00:00 · `{'secret_scanning': 'enabled', 'push_protection': 'disabled'}`

</details>

### VM-01 — Dependabot vulnerability alerts enabled: FAIL

Check: `github.dependabot_alerts_enabled` · params: `{}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | Dependabot alerts enabled |
| example-org/bad-repo | FAIL | Dependabot alerts disabled |

**Remediation:** Enable Dependabot alerts for every repository (org default for new repos).

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /repos/example-org/good-repo/vulnerability-alerts` · 2026-09-30T06:47:08.585333+00:00 · `{'http_status': 204}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/vulnerability-alerts` · 2026-09-30T06:47:08.585503+00:00 · `{'http_status': 404}`

</details>

### AC-02 — No public repositories unless allowlisted: FAIL

Check: `github.no_public_repos` · params: `{'allowlist': ['CodeReview']}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | visibility=private |
| example-org/bad-repo | FAIL | public and not allowlisted |

**Remediation:** Make the repository private/internal, or add it to the allowlist with a documented reason.

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /orgs/example-org/repos` · 2026-09-30T06:47:08.585519+00:00 · `{'visibility': 'private'}`
- `example-org/bad-repo` · `GET /orgs/example-org/repos` · 2026-09-30T06:47:08.585524+00:00 · `{'visibility': 'public'}`

</details>

### SC-01 — GitHub Actions references pinned to full commit SHAs: FAIL

Check: `github.actions_pinned_shas` · params: `{}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | 1 workflow file(s), all references pinned |
| example-org/bad-repo | FAIL | 3 unpinned action reference(s) |

**Remediation:** Replace tag/branch references (e.g. @v4) with the full 40-character commit SHA and keep the tag as a trailing comment; pin docker:// images by digest.

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /repos/example-org/good-repo/contents/.github/workflows` · 2026-09-30T06:47:08.586772+00:00 · `{'workflow_files': 1, 'unpinned': []}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/contents/.github/workflows` · 2026-09-30T06:47:08.587765+00:00 · `{'workflow_files': 1, 'unpinned': ['.github/workflows/build.yaml: actions/checkout@v4', '.github/workflows/build.yaml: some-org/some-action@main', '.github/workflows/build.yaml: docker://alpine:3.20']}`

</details>

### AC-03 — Default GITHUB_TOKEN permissions are read-only: FAIL

Check: `github.actions_default_token_read_only` · params: `{'allow_pr_approval': False}`

| Subject | Status | Detail |
|---|---|---|
| example-org | PASS | default_workflow_permissions=read, can_approve_pr_reviews=False |
| example-org/good-repo | PASS | default_workflow_permissions=read, can_approve_pr_reviews=False |
| example-org/bad-repo | FAIL | default_workflow_permissions=write, can_approve_pr_reviews=True |

**Remediation:** Set "Workflow permissions" to "Read repository contents and packages permissions" and disable "Allow GitHub Actions to create and approve pull requests" at org and repo level.

<details><summary>Evidence</summary>

- `example-org` · `GET /orgs/example-org/actions/permissions/workflow` · 2026-09-30T06:47:08.588011+00:00 · `{'default_workflow_permissions': 'read', 'can_approve_pr_reviews': False}`
- `example-org/good-repo` · `GET /repos/example-org/good-repo/actions/permissions/workflow` · 2026-09-30T06:47:08.588187+00:00 · `{'default_workflow_permissions': 'read', 'can_approve_pr_reviews': False}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/actions/permissions/workflow` · 2026-09-30T06:47:08.588440+00:00 · `{'default_workflow_permissions': 'write', 'can_approve_pr_reviews': True}`

</details>

### CM-02 — CODEOWNERS file present and valid: FAIL

Check: `github.codeowners_present` · params: `{}`

| Subject | Status | Detail |
|---|---|---|
| example-org/good-repo | PASS | .github/CODEOWNERS present, 0 syntax error(s) |
| example-org/bad-repo | FAIL | no CODEOWNERS file in .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS |

**Remediation:** Add a syntactically valid CODEOWNERS file under .github/, the root, or docs/.

<details><summary>Evidence</summary>

- `example-org/good-repo` · `GET /repos/example-org/good-repo/contents/.github/CODEOWNERS` · 2026-09-30T06:47:08.588746+00:00 · `{'found': True}`
- `example-org/good-repo` · `GET /repos/example-org/good-repo/codeowners/errors` · 2026-09-30T06:47:08.588750+00:00 · `{'error_count': 0}`
- `example-org/bad-repo` · `GET /repos/example-org/bad-repo/contents` · 2026-09-30T06:47:08.589214+00:00 · `{'searched': ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']}`

</details>

### AC-04 — Organisation owner count within threshold: PASS

Check: `github.org_admin_count` · params: `{'min_admins': 2, 'max_admins': 3}`

| Subject | Status | Detail |
|---|---|---|
| example-org | PASS | 2 org owner(s); allowed range 2..3 |


<details><summary>Evidence</summary>

- `example-org` · `GET /orgs/example-org/members` · 2026-09-30T06:47:08.589425+00:00 · `{'role': 'admin', 'count': 2}`

</details>

---
Framework IDs are an informal mapping for orientation only; this report is not an audit opinion
or certification.
