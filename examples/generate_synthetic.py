"""Regenerate examples/sample-report.md from the SYNTHETIC test fixtures (no network).

python examples/generate_synthetic.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentsec.catalog import load_catalog  # noqa: E402
from agentsec.collectors.github import GitHubClient, GitHubContext  # noqa: E402
from agentsec.recording import load_fixture, replay_transport  # noqa: E402
from agentsec.report import render_markdown  # noqa: E402
from agentsec.runner import run_catalog  # noqa: E402


def main() -> None:
    fixture = ROOT / "tests" / "fixtures" / "github" / "org_scenario.json"
    meta, routes = load_fixture(fixture)
    catalog_path = Path("controls/catalog.yaml")
    client = GitHubClient("synthetic", transport=replay_transport(routes))
    report = run_catalog(
        load_catalog(ROOT / catalog_path),
        target="github",
        org=meta["org"],
        context=GitHubContext(client=client, org=meta["org"]),
        catalog_path=catalog_path,
        data_source=f"replay:{fixture.name} (synthetic)",
    )
    out = ROOT / "examples" / "sample-report.md"
    out.write_text(render_markdown(report, synthetic=True), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
