# Controls mapping rationale

Framework references are **informal** and use criterion / control **IDs only**; wording below is
a paraphrase, not framework text. SOC 2 IDs refer to the AICPA Trust Services Criteria (2017,
revised points of focus 2022). ISO IDs refer to ISO/IEC 27001:2022 Annex A.

A passing technical check is **evidence supporting** a control, never proof that the control
is designed or operating effectively. Auditors assess controls; this tool collects evidence.

| Control | Check | SOC 2 | ISO 27001 | Rationale (paraphrased) |
|---|---|---|---|---|
| CM-01 | `branch_protection_enabled` | CC6.1, CC8.1 | A.8.4, A.8.32 | Changes to the production code line require peer review → change management and controlled write access to source code. Classic protection and rulesets both count. |
| AC-01 | `org_mfa_required` | CC6.1 | A.5.17, A.8.5 | Org membership requires a second factor → authentication strength for logical access. Does not prove phishing-resistant MFA. |
| DP-01 | `secret_scanning_enabled` | CC6.1, CC7.1 | A.5.17, A.8.12 | Detects and blocks committed credentials → protection of authentication information and leakage prevention. |
| VM-01 | `dependabot_alerts_enabled` | CC7.1 | A.8.8 | Known-vulnerable dependencies are surfaced → technical vulnerability identification. Does not prove alerts are triaged. |
| AC-02 | `no_public_repos` | CC6.1, C1.1 | A.5.15, A.8.4 | Source code exposure is intentional and approved (allowlist) → access control and confidentiality. |
| SC-01 | `actions_pinned_shas` | CC8.1, CC9.2 | A.5.21, A.8.28 | Third-party CI code is immutable per reference → supplier/supply-chain risk and secure development. |
| AC-03 | `actions_default_token_read_only` | CC6.1, CC6.3 | A.8.2, A.8.9 | CI tokens are least-privilege by default and cannot self-approve PRs → privileged access and secure configuration. |
| CM-02 | `codeowners_present` | CC8.1 | A.8.32 | Ownership of code paths is defined for review routing → change management. Presence ≠ enforcement (needs CM-01 with code-owner review). |
| AC-04 | `org_admin_count` | CC6.2, CC6.3 | A.5.18, A.8.2 | Number of org owners stays within a bounded range (≥ 2 for resilience, ≤ N for least privilege) → privileged access rights. |

## Status semantics

| Status | Meaning |
|---|---|
| PASS | Evidence collected and the condition holds for every subject. |
| FAIL | Evidence collected and the condition does not hold for at least one subject. |
| ERROR | Evidence could not be collected (permissions, rate limit, API error, no visible repos). Never treated as PASS. |

Aggregation per control: any FAIL → FAIL; else any ERROR → ERROR; else PASS. Zero findings → ERROR.

## Known gaps

- CM-01: if GitHub answers 403 "Upgrade to GitHub Pro…" (feature not in the org's plan,
  e.g. private repo on Free), that source counts as 0 required reviews and is noted in the
  evidence; any other 403 remains ERROR. Observed live on a private repo in a Free org.
- AC-02: allowlist entries match repository names case-insensitively (as GitHub does).
- Enterprise-level policies (enforced above the org) are not evaluated separately; the checks
  read the effective org/repo state.
- `ASSUMPTION`: visibility of `two_factor_requirement_enabled`, `security_and_analysis`, and
  workflow-permission endpoints depends on token permissions; missing fields produce ERROR.
