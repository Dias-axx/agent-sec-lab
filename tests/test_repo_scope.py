"""--repo: restrict checks to named repositories without listing the org's repos."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.collectors import github as gh
from agentsec.collectors.base import CollectorError
from agentsec.models import Status

from .conftest import FIXTURES, ROOT

CATALOG = ROOT / "controls" / "catalog.yaml"


def test_scoped_repos_skip_org_listing(github, requests_seen):
    github.only_repos = ["good-repo"]
    assert [r["full_name"] for r in github.repos()] == ["example-org/good-repo"]
    assert all(r.url.path != "/orgs/example-org/repos" for r in requests_seen)


def test_scoped_repo_missing_raises(github):
    github.only_repos = ["does-not-exist"]
    with pytest.raises(CollectorError, match="does-not-exist"):
        github.repos()


def test_scoped_repo_missing_is_error_finding(github):
    github.only_repos = ["does-not-exist"]
    [f] = gh.dependabot_alerts_enabled(github, {})
    assert f.status is Status.ERROR


def test_cli_repo_scope_in_report(tmp_path):
    res = CliRunner().invoke(
        app,
        ["run", "-c", str(CATALOG), "--replay", str(FIXTURES / "org_scenario.json"),
         "--repo", "good-repo", "--out", str(tmp_path)],
    )  # fmt: skip
    assert res.exit_code == 0, res.output  # good-repo + org settings are compliant
    md = (tmp_path / "report.md").read_text()
    assert "| Repository scope | good-repo |" in md
    assert "bad-repo" not in md


def test_report_scope_defaults_to_all(tmp_path):
    CliRunner().invoke(
        app,
        ["run", "-c", str(CATALOG), "--replay", str(FIXTURES / "org_scenario.json"),
         "--out", str(tmp_path)],
    )  # fmt: skip
    assert "| Repository scope | all visible repositories |" in (tmp_path / "report.md").read_text()
