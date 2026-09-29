"""Regenerate examples/sample-report.md from the SYNTHETIC test fixtures (no network).

python examples/generate_synthetic.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.conftest import ORG, load_scenario  # noqa: E402

from agentsec.catalog import load_catalog  # noqa: E402
from agentsec.collectors.github import GitHubClient, GitHubContext  # noqa: E402
from agentsec.report import render_markdown  # noqa: E402
from agentsec.runner import run_catalog  # noqa: E402


def main() -> None:
    routes = load_scenario()

    def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        if route.get("body") is None:
            return httpx.Response(route["status"])
        return httpx.Response(route["status"], json=route["body"])

    catalog_path = Path("controls/catalog.yaml")
    client = GitHubClient("synthetic", transport=httpx.MockTransport(handler))
    report = run_catalog(
        load_catalog(ROOT / catalog_path),
        target="github",
        org=ORG,
        context=GitHubContext(client=client, org=ORG),
        catalog_path=catalog_path,
    )
    out = ROOT / "examples" / "sample-report.md"
    out.write_text(render_markdown(report, synthetic=True), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
