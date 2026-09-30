# CLAUDE.md — agent-sec-lab

Public portfolio repo: (1) threat model for an untrusted-agent-code execution platform, (2) controls-as-code tool that maps SOC 2 / ISO 27001 controls to automated technical checks.
Owner: security engineer, regulated banking background. Goal: demonstrable, reproducible security engineering work. Not a product.

## Hard constraints (never violate)

- No employer data: no configs, logs, screenshots, incident details, vendor-internal details, hostnames, or internal naming. Everything is generic or lab-derived.
- No secrets in the repo. Use env vars / `.env.example` only. Add gitleaks pre-commit + CI check.
- Collectors run read-only against the owner's own test accounts (GitHub test org, Azure test subscription). Never target third-party systems.
- Never fabricate outputs, findings, benchmarks, versions, or API responses. Sample output must come from a real run against the test environment, or be labeled `SYNTHETIC EXAMPLE`.
- No destructive actions (delete, force-push, rewrite history, resource deletion) without explicit confirmation.
- Claims in docs = what the code demonstrably does. Mark assumptions as `ASSUMPTION`. Do not present the repo as production experience.

## Working rules for Claude Code

1. Plan first: state objective, scope, risks, steps, validation. Wait for approval before large changes.
2. Small commits, conventional messages (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
3. Patch, don't rewrite. Touch only affected files.
4. Every module ships with tests. Run tests and lint before declaring done; report actual results.
5. Ask when information is missing (e.g. tenant IDs, scopes). Do not guess.
6. Compact output: no filler, no restating context.

## Stack

- Python 3.11+, `uv` or `pip` + `pyproject.toml`
- `pydantic` (schemas), `pyyaml`, `httpx`, `typer` (CLI), `jinja2` (report)
- Tests: `pytest`, `pytest-httpx`/recorded fixtures; lint: `ruff`; types: `mypy`
- CI: GitHub Actions (lint, type, test, gitleaks, dependency audit via `pip-audit`)
- License: Apache-2.0

## Commands

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
agentsec validate --catalog controls/catalog.yaml
agentsec schema                                  # regenerate controls/catalog.schema.json
python examples/generate_synthetic.py            # regenerate SYNTHETIC sample report
agentsec run --org <ORG> --record tests/fixtures/github/recorded/<n>.json  # record live fixture
agentsec run --replay <fixture.json>             # offline run, no token
agentsec run --org <ORG> --repo <NAME> ...        # scope to named repos only
```

## Conventions

- `controls/catalog.schema.json` is generated from `src/agentsec/models.py`; never hand-edit.
- Collectors issue HTTP GET only. Any collection failure → `ERROR`, never `PASS`.
- New check = function in `collectors/<target>.py` + entry in its `SPEC.checks` + catalog entry
  + tests in `tests/` + row in `docs/controls-mapping.md`.
- Threat model tables are parsed by `tests/test_threat_model.py`: keep column order, IDs
  `T-NN` / `M-NN`, and bidirectional threat↔mitigation references.

## Phases

1. Scaffold: repo layout, pyproject, pre-commit, CI, LICENSE, SECURITY.md. Validate CI runs.
2. Threat model docs (Deliverable 1).
3. Catalog schema + loader + tests.
4. GitHub collector + 8 checks + tests with fixtures.
5. Runner + report + CLI; real run against test org; commit sample report.
6. README polish; tag `v0.1.0`.
7. Optional: Azure collector; Sigma rules; simulated postmortem (labeled lab exercise).

## Definition of done

- Tests, lint, type check, gitleaks, pip-audit all pass in CI.
- README, threat model, sample report present and consistent with actual behavior.
- No employer-derived content; no secrets; assumptions marked.
- Rollback: everything is git-tracked; releases tagged; no infra created except the owner's test org/subscription.

## Test environment

- GitHub test org: `dias-axx-lab` (owner-controlled, lab only). Token: fine-grained, read-only,
  supplied by the owner via `GITHUB_TOKEN`; never committed. Recordings use `--org-alias demo-org`
  and `--repo CodeReview` (token scoped to selected repositories; other org repos out of scope).
- Test repo `dias-axx-lab/CodeReview` is **public** on purpose (Free plan: rulesets, branch
  protection and secret scanning are only available for public repos) and allowlisted in AC-02.
- Live runs happen on the owner's machine. The Claude Code cloud session cannot reach
  `/orgs/...` endpoints (GitHub access there is repo-scoped).

## Open inputs (ask owner)

- Azure test subscription available? (phase 2)
