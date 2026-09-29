from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from agentsec.catalog import load_catalog
from agentsec.cli import app
from agentsec.collectors.github import GitHubClient, GitHubContext, org_mfa_required
from agentsec.models import Status
from agentsec.recording import (
    Recorder,
    load_fixture,
    minimize,
    parse_fixture,
    replay_transport,
)
from agentsec.runner import run_catalog

from .conftest import FIXTURES, ROOT

CATALOG = ROOT / "controls" / "catalog.yaml"
REAL_ORG = "real-org"
TOKEN = "ghp_test_token_never_recorded"


@pytest.fixture
def upstream(httpx_mock):
    """Fake live API: synthetic scenario renamed to REAL_ORG plus fields that must be dropped."""
    text = (FIXTURES / "org_scenario.json").read_text().replace("example-org", REAL_ORG)
    _, routes = parse_fixture(json.loads(text))
    routes[f"/orgs/{REAL_ORG}"]["body"]["billing_email"] = "owner@example.test"
    routes[f"/orgs/{REAL_ORG}/members"]["body"] = [
        {"login": "alice-real", "email": "alice@example.test", "avatar_url": "https://x"},
        {"login": "bob-real", "id": 42},
    ]
    for r in routes[f"/orgs/{REAL_ORG}/repos"]["body"]:
        r["owner"] = {"login": REAL_ORG, "html_url": "https://github.com/real-org"}
        r["clone_url"] = f"https://github.com/{r['full_name']}.git"

    def respond(request: httpx.Request) -> httpx.Response:
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        if route.get("body") is None:
            return httpx.Response(route["status"])
        return httpx.Response(route["status"], json=route["body"])

    httpx_mock.add_callback(respond, is_reusable=True, is_optional=True)
    return routes


def _live_run(org_alias: str | None = None):
    rec = Recorder(REAL_ORG, org_alias=org_alias)
    client = GitHubClient(TOKEN, on_response=rec)
    ctx = GitHubContext(client=client, org=REAL_ORG)
    report = run_catalog(
        load_catalog(CATALOG), target="github", org=REAL_ORG, context=ctx, catalog_path=CATALOG
    )
    client.close()
    return rec, report


def test_minimize_drops_unlisted_fields():
    assert minimize({"login": "a", "email": "x", "nested": {"name": "n"}, "name": "k"}) == {
        "login": "a",
        "name": "k",
    }
    assert minimize([{"status": "enabled", "url": "u"}]) == [{"status": "enabled"}]


def test_record_then_replay_gives_same_results(upstream, tmp_path):
    rec, live = _live_run()
    path = rec.save(tmp_path / "rec.json", api_url="https://api.github.com")
    meta, routes = load_fixture(path)
    assert meta["kind"] == "recorded" and meta["org"] == REAL_ORG

    client = GitHubClient("replay", transport=replay_transport(routes, strict=True))
    replayed = run_catalog(
        load_catalog(CATALOG),
        target="github",
        org=REAL_ORG,
        context=GitHubContext(client=client, org=REAL_ORG),
        catalog_path=CATALOG,
    )
    assert [(r.control.id, r.status) for r in replayed.results] == [
        (r.control.id, r.status) for r in live.results
    ]
    assert all(f.status is not Status.ERROR for r in replayed.results for f in r.findings)


def test_recording_is_minimised_and_pseudonymised(upstream, tmp_path):
    rec, _ = _live_run(org_alias="demo-org")
    text = rec.save(tmp_path / "rec.json", api_url="https://api.github.com").read_text()
    for leaked in (TOKEN, REAL_ORG, "alice-real", "bob-real", "@example.test", "clone_url"):
        assert leaked not in text, leaked
    doc = json.loads(text)
    assert doc["_meta"]["org"] == "demo-org"
    assert [m["login"] for m in doc["/orgs/demo-org/members"]["body"]] == ["user-1", "user-2"]
    assert doc["/repos/demo-org/good-repo"]["body"]["full_name"] == "demo-org/good-repo"
    assert doc["/repos/demo-org/bad-repo/vulnerability-alerts"]["status"] == 404


def test_pagination_pages_are_merged(httpx_mock):
    base = "https://api.github.com/orgs/o/members"
    httpx_mock.add_response(
        url=f"{base}?per_page=100&role=admin",
        json=[{"login": "a"}],
        headers={"Link": f'<{base}?role=admin&per_page=100&page=2>; rel="next"'},
    )
    httpx_mock.add_response(url=f"{base}?role=admin&per_page=100&page=2", json=[{"login": "b"}])
    rec = Recorder("o")
    list(GitHubClient("t", on_response=rec).paginate("/orgs/o/members", {"role": "admin"}))
    assert rec.routes["/orgs/o/members"]["body"] == [{"login": "user-1"}, {"login": "user-2"}]


def test_rate_limit_headers_recorded(httpx_mock):
    httpx_mock.add_response(
        status_code=429, json={"message": "slow"}, headers={"retry-after": "30", "x-other": "1"}
    )
    rec = Recorder("o")
    [f] = org_mfa_required(GitHubContext(client=GitHubClient("t", on_response=rec), org="o"), {})
    assert f.status is Status.ERROR
    assert rec.routes["/orgs/o"]["headers"] == {"retry-after": "30"}


def test_strict_replay_unknown_path_is_error():
    client = GitHubClient("r", transport=replay_transport({}, strict=True))
    [f] = org_mfa_required(GitHubContext(client=client, org="o"), {})
    assert f.status is Status.ERROR


def test_replay_rejects_non_get():
    with httpx.Client(transport=replay_transport({})) as c:
        assert c.post("http://x/orgs/o").status_code == 405


def test_cli_replay_synthetic(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    res = CliRunner().invoke(
        app,
        ["run", "-c", str(CATALOG), "--replay", str(FIXTURES / "org_scenario.json"),
         "--out", str(tmp_path)],
    )  # fmt: skip
    assert res.exit_code == 1, res.output
    md = (tmp_path / "report.md").read_text()
    assert "SYNTHETIC EXAMPLE" in md
    assert "replay:org_scenario.json (synthetic)" in md


def test_cli_record_writes_fixture(upstream, tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    fixture = tmp_path / "recorded" / "org.json"
    res = CliRunner().invoke(
        app,
        ["run", "-c", str(CATALOG), "--org", REAL_ORG, "--record", str(fixture),
         "--org-alias", "demo-org", "--out", str(tmp_path / "out")],
    )  # fmt: skip
    assert res.exit_code == 1, res.output
    assert fixture.exists() and TOKEN not in fixture.read_text()
    assert "SYNTHETIC" not in (tmp_path / "out" / "report.md").read_text()


def test_cli_record_and_replay_exclusive(tmp_path):
    res = CliRunner().invoke(
        app,
        ["run", "-c", str(CATALOG), "--replay", str(FIXTURES / "org_scenario.json"),
         "--record", str(tmp_path / "x.json")],
    )  # fmt: skip
    assert res.exit_code == 3


RECORDED = sorted((FIXTURES / "recorded").glob("*.json"))


@pytest.mark.skipif(not RECORDED, reason="no recorded fixtures committed yet")
@pytest.mark.parametrize("fixture", RECORDED, ids=lambda p: p.name)
def test_recorded_fixtures_replay_cleanly(fixture):
    """Every committed recording must replay without missing paths (strict)."""
    meta, routes = load_fixture(fixture)
    assert meta.get("kind") == "recorded"
    client = GitHubClient("replay", transport=replay_transport(routes, strict=True))
    report = run_catalog(
        load_catalog(CATALOG),
        target="github",
        org=meta["org"],
        context=GitHubContext(client=client, org=meta["org"]),
        catalog_path=CATALOG,
    )
    missing = [f.detail for r in report.results for f in r.findings if "not in fixture" in f.detail]
    assert not missing, f"re-record {fixture.name}: catalog needs paths not in fixture"


def test_file_content_dropped_except_workflows(httpx_mock):
    # Observed live: CODEOWNERS content (base64) carried the real owner login.
    import base64

    enc = base64.b64encode(b"* @real-owner\n").decode()
    httpx_mock.add_response(
        url="https://api.github.com/repos/o/r/contents/.github/CODEOWNERS",
        json={"name": "CODEOWNERS", "type": "file", "content": enc, "encoding": "base64"},
    )
    wf = base64.b64encode(b"jobs: {}\n").decode()
    httpx_mock.add_response(
        url="https://api.github.com/repos/o/r/contents/.github/workflows/ci.yml",
        json={"name": "ci.yml", "type": "file", "content": wf, "encoding": "base64"},
    )
    rec = Recorder("o")
    client = GitHubClient("t", on_response=rec)
    client.get_json("/repos/o/r/contents/.github/CODEOWNERS")
    client.get_json("/repos/o/r/contents/.github/workflows/ci.yml")
    assert "content" not in rec.routes["/repos/o/r/contents/.github/CODEOWNERS"]["body"]
    assert rec.routes["/repos/o/r/contents/.github/workflows/ci.yml"]["body"]["content"] == wf
