"""Command-line interface."""

from __future__ import annotations

import os
from pathlib import Path

import typer

from agentsec.catalog import CatalogError, load_catalog, write_schema
from agentsec.collectors.base import CollectorError
from agentsec.collectors.github import DEFAULT_BASE_URL, GitHubClient, GitHubContext
from agentsec.models import Severity
from agentsec.report import write_reports
from agentsec.runner import exit_code, run_catalog

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)

CATALOG_OPT = typer.Option(Path("controls/catalog.yaml"), "--catalog", "-c", exists=True)


@app.command()
def validate(catalog: Path = CATALOG_OPT) -> None:
    """Validate the catalog against the schema and collector registry."""
    try:
        cat = load_catalog(catalog)
    except CatalogError as exc:
        typer.echo(f"INVALID: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"OK: {len(cat.controls)} controls")


@app.command()
def schema(out: Path = typer.Option(Path("controls/catalog.schema.json"), "--out")) -> None:
    """Regenerate the catalog JSON schema from the pydantic models."""
    write_schema(out)
    typer.echo(f"wrote {out}")


@app.command()
def run(
    catalog: Path = CATALOG_OPT,
    target: str = typer.Option("github", "--target", "-t"),
    org: str = typer.Option(..., "--org", help="Organisation you own / are authorised to assess"),
    out: Path = typer.Option(Path("reports"), "--out", "-o"),
    fail_on: Severity = typer.Option(Severity.HIGH, "--fail-on"),
    include_archived: bool = typer.Option(False, "--include-archived"),
    api_url: str = typer.Option(DEFAULT_BASE_URL, "--api-url", envvar="GITHUB_API_URL"),
) -> None:
    """Run read-only checks and write report.md + report.json.

    Exit codes: 0 clean, 1 FAIL >= --fail-on, 2 ERROR >= --fail-on (no FAIL), 3 usage/setup error.
    """
    if target != "github":
        typer.echo(f"unsupported target: {target}", err=True)
        raise typer.Exit(3)
    try:
        cat = load_catalog(catalog)
        client = GitHubClient(os.environ.get("GITHUB_TOKEN", ""), base_url=api_url)
    except (CatalogError, CollectorError) as exc:
        typer.echo(f"setup error: {exc}", err=True)
        raise typer.Exit(3) from exc
    try:
        ctx = GitHubContext(client=client, org=org, include_archived=include_archived)
        report = run_catalog(cat, target=target, org=org, context=ctx, catalog_path=catalog)
    finally:
        client.close()
    md, js = write_reports(report, out)
    c = report.counts()
    typer.echo(f"PASS={c['PASS']} FAIL={c['FAIL']} ERROR={c['ERROR']} -> {md}, {js}")
    raise typer.Exit(exit_code(report, fail_on))


if __name__ == "__main__":
    app()
