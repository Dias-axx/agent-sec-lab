from __future__ import annotations

import pytest

from agentsec.collectors import github as gh
from agentsec.models import Status

GOOD = "example-org/good-repo"
BAD = "example-org/bad-repo"


def test_archived_repos_excluded_by_default(github):
    names = [r["full_name"] for r in github.repos()]
    assert names == [GOOD, BAD]


def test_branch_protection(github, by_subject):
    f = by_subject(gh.branch_protection_enabled(github, {"required_reviews": 1}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL


def test_branch_protection_counts_rulesets(github, routes, by_subject):
    routes["/repos/example-org/bad-repo/rules/branches/main"]["body"] = [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 2}}
    ]
    f = by_subject(gh.branch_protection_enabled(github, {"required_reviews": 2}))
    assert f[BAD].status is Status.PASS
    assert f[GOOD].status is Status.FAIL  # classic protection only requires 1


def test_branch_protection_forbidden_is_error(github, routes, by_subject):
    routes["/repos/example-org/good-repo/branches/main/protection"] = {
        "status": 403,
        "body": {"message": "Resource not accessible by personal access token"},
    }
    f = by_subject(gh.branch_protection_enabled(github, {}))
    assert f[GOOD].status is Status.ERROR
    assert "403" in f[GOOD].detail


def test_branch_protection_other_404_is_error(github, routes, by_subject):
    routes["/repos/example-org/good-repo/branches/main/protection"] = {
        "status": 404,
        "body": {"message": "Not Found"},
    }
    f = by_subject(gh.branch_protection_enabled(github, {}))
    assert f[GOOD].status is Status.ERROR


@pytest.mark.parametrize(("value", "expected"), [(True, Status.PASS), (False, Status.FAIL)])
def test_org_mfa(github, routes, value, expected):
    routes["/orgs/example-org"]["body"]["two_factor_requirement_enabled"] = value
    [f] = gh.org_mfa_required(github, {})
    assert f.status is expected


def test_org_mfa_not_visible_is_error(github, routes):
    del routes["/orgs/example-org"]["body"]["two_factor_requirement_enabled"]
    [f] = gh.org_mfa_required(github, {})
    assert f.status is Status.ERROR


def test_secret_scanning(github, by_subject):
    f = by_subject(gh.secret_scanning_enabled(github, {"require_push_protection": True}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL
    f = by_subject(gh.secret_scanning_enabled(github, {"require_push_protection": False}))
    assert f[BAD].status is Status.PASS


def test_secret_scanning_field_missing_is_error(github, routes, by_subject):
    del routes["/repos/example-org/good-repo"]["body"]["security_and_analysis"]
    f = by_subject(gh.secret_scanning_enabled(github, {}))
    assert f[GOOD].status is Status.ERROR


def test_dependabot(github, by_subject):
    f = by_subject(gh.dependabot_alerts_enabled(github, {}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL


def test_dependabot_forbidden_is_error(github, routes, by_subject):
    routes["/repos/example-org/good-repo/vulnerability-alerts"] = {
        "status": 403,
        "body": {"message": "Forbidden"},
    }
    f = by_subject(gh.dependabot_alerts_enabled(github, {}))
    assert f[GOOD].status is Status.ERROR


def test_public_repos(github, by_subject):
    f = by_subject(gh.no_public_repos(github, {"allowlist": []}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL
    f = by_subject(gh.no_public_repos(github, {"allowlist": ["bad-repo"]}))
    assert f[BAD].status is Status.PASS


@pytest.mark.parametrize(
    ("uses", "pinned"),
    [
        ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", True),
        ("actions/checkout@v4", False),
        ("actions/checkout@3d3c42e", False),
        ("actions/checkout", False),
        ("org/repo/.github/workflows/x.yml@main", False),
        ("./.github/actions/local", True),
        ("docker://alpine:3.20", False),
        ("docker://alpine@sha256:" + "0" * 64, True),
    ],
)
def test_is_pinned(uses, pinned):
    assert gh.is_pinned(uses) is pinned


def test_actions_pinned(github, by_subject):
    f = by_subject(gh.actions_pinned_shas(github, {}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL
    assert len(f[BAD].evidence[0].excerpt["unpinned"]) == 3


def test_actions_pinned_no_workflows(github, routes, by_subject):
    del routes["/repos/example-org/good-repo/contents/.github/workflows"]
    f = by_subject(gh.actions_pinned_shas(github, {}))
    assert f[GOOD].status is Status.PASS


def test_actions_pinned_invalid_yaml_is_error(github, routes, by_subject):
    routes["/repos/example-org/good-repo/contents/.github/workflows/ci.yml"]["body"]["content"] = (
        "!!!not-base64"
    )
    f = by_subject(gh.actions_pinned_shas(github, {}))
    assert f[GOOD].status is Status.ERROR


def test_token_permissions(github, by_subject):
    f = by_subject(gh.actions_default_token_read_only(github, {}))
    assert f["example-org"].status is Status.PASS
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL


def test_codeowners(github, by_subject):
    f = by_subject(gh.codeowners_present(github, {}))
    assert f[GOOD].status is Status.PASS
    assert f[BAD].status is Status.FAIL


def test_codeowners_syntax_errors_fail(github, routes, by_subject):
    routes["/repos/example-org/good-repo/codeowners/errors"]["body"]["errors"] = [
        {"line": 1, "kind": "Unknown owner"}
    ]
    f = by_subject(gh.codeowners_present(github, {}))
    assert f[GOOD].status is Status.FAIL


@pytest.mark.parametrize(
    ("owners", "expected"), [(1, Status.FAIL), (2, Status.PASS), (3, Status.PASS), (4, Status.FAIL)]
)
def test_admin_count(github, routes, owners, expected):
    routes["/orgs/example-org/members"]["body"] = [{"login": f"u{i}"} for i in range(owners)]
    [f] = gh.org_admin_count(github, {"min_admins": 2, "max_admins": 3})
    assert f.status is expected


def test_no_visible_repos_is_error(github, routes):
    routes["/orgs/example-org/repos"]["body"] = []
    [f] = gh.dependabot_alerts_enabled(github, {})
    assert f.status is Status.ERROR


PLAN_MSG = "Upgrade to GitHub Pro or make this repository public to enable this feature."


def test_branch_protection_plan_limited_rulesets_uses_classic(github, routes, by_subject):
    # Observed live on a private repo in a Free org: rulesets endpoint 403 with plan message.
    routes["/repos/example-org/good-repo/rules/branches/main"] = {
        "status": 403,
        "body": {"message": PLAN_MSG},
    }
    f = by_subject(gh.branch_protection_enabled(github, {"required_reviews": 1}))
    assert f[GOOD].status is Status.PASS
    assert any(e.excerpt.get("plan_unavailable") for e in f[GOOD].evidence)


def test_branch_protection_plan_limited_everywhere_fails(github, routes, by_subject):
    for path in (
        "/repos/example-org/good-repo/branches/main/protection",
        "/repos/example-org/good-repo/rules/branches/main",
    ):
        routes[path] = {"status": 403, "body": {"message": PLAN_MSG}}
    f = by_subject(gh.branch_protection_enabled(github, {"required_reviews": 1}))
    assert f[GOOD].status is Status.FAIL
    assert "not available on current GitHub plan" in f[GOOD].detail


def test_branch_protection_other_403_still_error(github, routes, by_subject):
    routes["/repos/example-org/good-repo/rules/branches/main"] = {
        "status": 403,
        "body": {"message": "Resource not accessible by integration"},
    }
    f = by_subject(gh.branch_protection_enabled(github, {}))
    assert f[GOOD].status is Status.ERROR


def test_public_repo_allowlist_is_case_insensitive(github, by_subject):
    f = by_subject(gh.no_public_repos(github, {"allowlist": ["BAD-Repo"]}))
    assert f[BAD].status is Status.PASS
