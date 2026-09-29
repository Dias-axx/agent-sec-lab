"""Render reports as Markdown and JSON."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, StrictUndefined

from agentsec.models import Report

_TEMPLATE = """\
# agentsec report — {{ m.target }} / {{ m.org }}

{% if synthetic -%}
> **SYNTHETIC EXAMPLE** — generated from test fixtures, not from a real environment.

{% endif -%}
| Field | Value |
|---|---|
| Tool version | {{ m.tool_version }} |
| Catalog | `{{ m.catalog_path }}` (sha256 `{{ m.catalog_sha256[:12] }}…`) |
| Started (UTC) | {{ m.started_at.isoformat() }} |
| Finished (UTC) | {{ m.finished_at.isoformat() }} |

## Summary

| PASS | FAIL | ERROR |
|---|---|---|
| {{ counts.PASS }} | {{ counts.FAIL }} | {{ counts.ERROR }} |

| Control | Title | Severity | SOC 2 | ISO 27001 | Status |
|---|---|---|---|---|---|
{% for r in results -%}
| {{ r.control.id }} | {{ r.control.title }} | {{ r.control.severity.value }} \
| {{ r.control.frameworks.soc2 | join(", ") }} | {{ r.control.frameworks.iso27001 | join(", ") }} \
| **{{ r.status.value }}** |
{% endfor %}
## Details
{% for r in results %}
### {{ r.control.id }} — {{ r.control.title }}: {{ r.status.value }}

Check: `{{ r.control.collector }}.{{ r.control.check }}` · params: `{{ r.control.params }}`

| Subject | Status | Detail |
|---|---|---|
{% for f in r.findings -%}
| {{ f.subject }} | {{ f.status.value }} | {{ f.detail | replace("|", "\\\\|") }} |
{% endfor %}
{% if r.status.value != "PASS" -%}
**Remediation:** {{ r.control.remediation }}
{% endif %}
<details><summary>Evidence</summary>

{% for f in r.findings -%}
{% for e in f.evidence -%}
- `{{ f.subject }}` · `GET {{ e.endpoint }}` · {{ e.collected_at.isoformat() }} · `{{ e.excerpt }}`
{% endfor -%}
{% endfor %}
</details>
{% endfor %}
---
Framework IDs are an informal mapping for orientation only; this report is not an audit opinion
or certification.
"""


def render_markdown(report: Report, *, synthetic: bool = False) -> str:
    env = Environment(autoescape=False, undefined=StrictUndefined, keep_trailing_newline=True)  # noqa: S701 - Markdown output, not HTML
    return env.from_string(_TEMPLATE).render(
        m=report.metadata,
        counts=report.counts(),
        results=report.results,
        synthetic=synthetic,
    )


def write_reports(report: Report, out_dir: Path, *, synthetic: bool = False) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "report.md"
    js = out_dir / "report.json"
    md.write_text(render_markdown(report, synthetic=synthetic), encoding="utf-8")
    js.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return md, js
