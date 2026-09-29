# GitHub API fixtures

**SYNTHETIC EXAMPLE.** These JSON files are hand-written, not recorded from a live API.
Field names and status-code semantics follow the public GitHub REST API documentation
(API version `2022-11-28`). Only fields the checks read are included.

`org_scenario.json` maps request path → `{status, body, headers?}` for a fictional org
`example-org` with two repos:

- `good-repo` — private, compliant with every control.
- `bad-repo` — public, non-compliant with every repo-level control.

A `content_text` key in a body is base64-encoded into `content` by `tests/conftest.py`
(keeps workflow YAML readable).

Replace with recorded, scrubbed responses from the owner's test org once available.
