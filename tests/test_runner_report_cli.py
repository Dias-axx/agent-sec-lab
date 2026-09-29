from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from agentsec.catalog import load_catalog
from agentsec.cli import app
from agentsec.models import Severity, Status
from agentsec.report import render_markdown, write_reports
from agentsec.runner import exit_code, run_catalog

from .conftest import ORG, ROOT

CATALOG = ROOT / "controls" / "catalog.yaml"


@pytest.fixture
def report(github):
    return run_catalog(
        load_catalog(CATALOG), target="github", org=ORG, context=github, catalog_path=CATALOG
    )


def test_run_produces_result_per_control(report):
    statuses = {r.control.id: r.status for r in report.results}
    assert len(statuses) == 9
    assert statuses["AC-01"] is Status.PASS
    assert statuses["AC-04"] is Status.PASS
    assert statuses["CM-01"] is Status.FAIL  # bad-repo unprotected


def test_check_exception_becomes_error(github, monkeypatch):
    from agentsec.collectors import github as gh

    def boom(ctx, params):
        raise RuntimeError("unexpected")

    monkeypatch.setitem(gh.SPEC.checks, "org_mfa_required", boom)  # type: ignore[index]
    rep = run_catalog(
        load_catalog(CATALOG), target="github", org=ORG, context=github, catalog_path=CATALOG
    )
    ac01 = next(r for r in rep.results if r.control.id == "AC-01")
    assert ac01.status is Status.ERROR


def test_aggregate_rules():
    from agentsec.models import Finding, Result

    def f(s):
        return Finding(subject="x", status=s, detail="")

    assert Result.aggregate([]) is Status.ERROR
    assert Result.aggregate([f(Status.PASS)]) is Status.PASS
    assert Result.aggregate([f(Status.PASS), f(Status.ERROR)]) is Status.ERROR
    assert Result.aggregate([f(Status.ERROR), f(Status.FAIL)]) is Status.FAIL


def test_exit_code_thresholds(report):
    assert exit_code(report, Severity.HIGH) == 1
    for r in report.results:
        if r.status is Status.FAIL:
            r.status = Status.PASS
    assert exit_code(report, Severity.LOW) == 0
    report.results[0].status = Status.ERROR
    assert exit_code(report, Severity.LOW) == 2


def test_reports_written(report, tmp_path):
    md, js = write_reports(report, tmp_path)
    text = md.read_text()
    assert "## Summary" in text and "CM-01" in text and "Remediation" in text
    data = json.loads(js.read_text())
    assert data["metadata"]["org"] == ORG
    assert "test-token-not-real" not in text + js.read_text()


def test_synthetic_banner(report):
    assert "SYNTHETIC EXAMPLE" in render_markdown(report, synthetic=True)
    assert "SYNTHETIC EXAMPLE" not in render_markdown(report)


def test_cli_validate_ok():
    res = CliRunner().invoke(app, ["validate", "--catalog", str(CATALOG)])
    assert res.exit_code == 0, res.output
    assert "OK: 9 controls" in res.output


def test_cli_run_without_token_is_setup_error(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    res = CliRunner().invoke(
        app, ["run", "--catalog", str(CATALOG), "--org", ORG, "--out", str(tmp_path)]
    )
    assert res.exit_code == 3


def test_cli_run_end_to_end(github, monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-not-real")
    res = CliRunner().invoke(
        app, ["run", "--catalog", str(CATALOG), "--org", ORG, "--out", str(tmp_path)]
    )
    assert res.exit_code == 1, res.output  # high-severity FAILs in scenario
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()
