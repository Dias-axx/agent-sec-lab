# Mitigations and residual risk

Every mitigation references at least one threat in [threats.md](threats.md). "agentsec" marks
controls that the controls-as-code tool in this repo checks automatically today (GitHub only).

| ID | Mitigation | Threats | Type | agentsec control |
|---|---|---|---|---|
| M-01 | Strong sandbox isolation: microVM or user-space-kernel class runtime; one sandbox per job, never reused; rootless, all capabilities dropped, seccomp/AppArmor profile, read-only root FS, no host mounts or runtime socket; scratch volumes destroyed at teardown | T-01, T-02, T-05, T-06 | Preventive | — |
| M-02 | Host hardening and patch SLA for kernel/hypervisor/runtime; dedicated node pools for untrusted workloads; no co-location with platform services | T-01, T-06, T-32 | Preventive | — |
| M-03 | Deny-by-default egress: sandbox traffic only via egress proxy with per-tenant allowlist; controlled DNS resolver with logging; link-local/metadata ranges blocked; payload size limits | T-03, T-08, T-10, T-19, T-32 | Preventive, detective | — |
| M-04 | Tool broker: capability-scoped tools with explicit schemas; credentials injected server-side and never returned to the sandbox; secret-pattern redaction on tool outputs; per-tool rate limits | T-07, T-10, T-30 | Preventive | — |
| M-05 | Policy enforcement independent of the LLM: allow-listed tool actions per task type, human approval for high-impact actions (external writes, payments, deletes), all model output and data treated as untrusted input | T-09, T-10 | Preventive | — |
| M-06 | Per-tenant isolation in the data layer: tenant-scoped buckets/prefixes, per-tenant KMS keys, tenant ID derived from authenticated context only, authorization checks server-side with negative tests | T-04, T-24, T-33 | Preventive | — |
| M-07 | Least-privilege workload and human identities: one identity per component, no wildcards, periodic access review and unused-permission removal, bounded owner/admin count | T-24, T-25, T-26, T-33 | Preventive | AC-04 |
| M-08 | Short-lived credentials: OIDC federation / token exchange, job credentials with TTL ≤ job duration, no static keys; secret scanning with push protection | T-07, T-13, T-25 | Preventive, detective | DP-01 |
| M-09 | Resource governance: CPU/memory/pids/wall-clock limits per sandbox, per-tenant quotas and API rate limits, cost budgets with alerts | T-11, T-12, T-30 | Preventive, detective | — |
| M-10 | Robust tenant authN/authZ: OIDC with issuer/audience/expiry validation, token rotation, scoped tokens, authz regression tests in CI | T-13, T-14 | Preventive | — |
| M-11 | Immutable audit logging: append-only delivery to a separate log account, WORM retention (object lock), hash chaining, heartbeat and gap detection, alerts on logging config changes | T-16, T-22, T-23 | Detective | — |
| M-12 | Attribution: every event carries tenant ID, job ID, sandbox ID, and acting identity; log schema validated in the pipeline | T-23 | Detective | — |
| M-13 | Retention/deletion enforcement: data classification with TTL per contract; lifecycle policies incl. backups and caches; crypto-shredding via per-tenant key deletion; deletion receipts recorded in audit log | T-15, T-16 | Preventive, corrective | — |
| M-14 | Third-party processor controls: contract terms for zero retention / no training, data-flow inventory, per-tenant opt-in before data reaches a provider, minimisation of data in prompts | T-17 | Preventive (contractual + technical) | — |
| M-15 | Dependency supply chain: pinned versions with hashes, SBOM per build, vulnerability audit in CI, private package mirror with allowlist for runtime installs | T-18, T-19 | Preventive, detective | VM-01 |
| M-16 | Image integrity: images signed at build, admission policy verifying signatures and digests, regular base-image rebuilds | T-18, T-20 | Preventive | — |
| M-17 | CI/CD hardening: third-party actions pinned to commit SHAs, read-only default workflow token, OIDC to cloud instead of stored keys, branch protection with reviews, CODEOWNERS | T-21 | Preventive | SC-01, AC-03, CM-01, CM-02 |
| M-18 | Privileged access: phishing-resistant MFA, just-in-time access with approval, monitored break-glass accounts, session recording | T-26, T-27 | Preventive, detective | AC-01 |
| M-19 | Artifact integrity: content-addressed, write-once artifact store; signed artifacts; eval pipeline identity separate from job identities | T-28 | Preventive, detective | — |
| M-20 | Error sanitisation: generic client errors, no stack traces, non-enumerable resource IDs, uniform 404/403 behaviour | T-29 | Preventive | — |
| M-21 | Transport security: TLS 1.2+ with certificate validation enforced; code scanning for disabled verification; no TLS interception except explicitly inspected allowlist | T-31 | Preventive | — |
| M-22 | Network segmentation: sandbox network namespace without routes to internal CIDRs or metadata; service-to-service mTLS with authorization | T-03, T-32 | Preventive | — |

## Residual risk

| Area | Threats | Residual | Rationale |
|---|---|---|---|
| Zero-day sandbox/hypervisor escape | T-01, T-06 | **Medium** | Isolation reduces but does not eliminate unknown kernel/hypervisor bugs; detection is best-effort. Accept with patch SLA and runtime monitoring. |
| Prompt injection → tool abuse / exfiltration | T-09, T-10 | **Medium** | No complete technical fix for prompt injection exists. Mitigation relies on constraining what the agent *can* do (M-03, M-04, M-05), not on detecting malicious prompts. |
| Secret/data exfiltration via allowed channels | T-07, T-08 | **Medium** | Allowlisted destinations can still be abused; data-in-URL and low-rate DNS channels are hard to detect reliably. |
| Retention and third-party processing | T-15, T-17 | **Medium** | Depends partly on third-party behaviour and contracts; technical verification of provider-side deletion is limited. |
| Supply chain | T-18 | **Medium** | Pinning and signing prevent silent drift but not a malicious release that is pinned deliberately. |
| Insider / stolen tenant tokens | T-13, T-26 | **Medium** | Legitimate-looking access; detection relies on behavioural baselines. |
| All other threats | — | **Low** | Covered by preventive controls with detection signals. |

## Assumptions and limitations

- `ASSUMPTION`: the cloud provider offers workload identity federation, object lock/WORM storage,
  per-key KMS policies, and an admission-control mechanism for image signatures.
- Ratings are qualitative and reflect the reference design, not a measured environment.
- This threat model has not been validated by penetration testing.
