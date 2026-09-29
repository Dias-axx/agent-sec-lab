# Security Policy

## Scope

This is a lab / portfolio repository. It is not a product and is not production-hardened.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's
"Report a vulnerability" (private security advisory) on this repository.
Do not open a public issue for security reports.

Include: affected file/version, reproduction steps, and impact.
Expect an acknowledgement on a best-effort basis; there is no SLA.

## Safe-use notice

- `agentsec` performs **read-only** API calls. Run it only against organisations and
  subscriptions you own or are explicitly authorised to assess.
- Supply credentials via environment variables only. Never commit tokens.
- Reports can contain repository names and configuration details of the assessed org.
  Treat generated reports as internal data.

## Repository hygiene

- gitleaks runs in pre-commit and in CI over full git history.
- Third-party GitHub Actions are pinned to commit SHAs.
- Dependencies are audited with `pip-audit` in CI.
