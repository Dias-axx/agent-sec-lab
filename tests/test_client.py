from __future__ import annotations

import httpx
import pytest

from agentsec.collectors.base import ApiError, CollectorError, RateLimitError
from agentsec.collectors.github import GitHubClient, GitHubContext
from agentsec.models import Status


def test_empty_token_rejected():
    with pytest.raises(CollectorError):
        GitHubClient("")


def test_only_get_requests_and_headers(github, requests_seen):
    github.repos()
    assert requests_seen
    for req in requests_seen:
        assert req.method == "GET"
        assert req.headers["Authorization"] == "Bearer test-token-not-real"
        assert req.headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_pagination_follows_link_header(httpx_mock):
    base = "https://api.github.com/orgs/o/members"
    httpx_mock.add_response(
        url=f"{base}?per_page=100&role=admin",
        json=[{"login": "a"}],
        headers={"Link": f'<{base}?role=admin&per_page=100&page=2>; rel="next"'},
    )
    httpx_mock.add_response(url=f"{base}?role=admin&per_page=100&page=2", json=[{"login": "b"}])
    client = GitHubClient("t")
    assert [m["login"] for m in client.paginate("/orgs/o/members", {"role": "admin"})] == [
        "a",
        "b",
    ]


def test_rate_limit_raises(httpx_mock):
    httpx_mock.add_response(
        status_code=403,
        json={"message": "API rate limit exceeded"},
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"},
    )
    with pytest.raises(RateLimitError):
        GitHubClient("t").get_json("/orgs/o")


def test_server_error_raises(httpx_mock):
    httpx_mock.add_response(status_code=502, json={"message": "Bad Gateway"})
    with pytest.raises(ApiError):
        GitHubClient("t").get_raw("/orgs/o")


def test_transport_error_is_api_error(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectTimeout("boom"))
    with pytest.raises(ApiError) as exc:
        GitHubClient("t").get_json("/orgs/o")
    assert exc.value.status == 0


def test_rate_limit_surfaces_as_error_finding(httpx_mock):
    httpx_mock.add_response(
        status_code=429, json={"message": "slow down"}, headers={"retry-after": "60"}
    )
    from agentsec.collectors.github import org_mfa_required

    ctx = GitHubContext(client=GitHubClient("t"), org="o")
    [f] = org_mfa_required(ctx, {})
    assert f.status is Status.ERROR
    assert "rate limited" in f.detail
