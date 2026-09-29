from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from agentsec.collectors.github import GitHubClient, GitHubContext

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "github"
ORG = "example-org"

Routes = dict[str, dict[str, Any]]


def load_scenario() -> Routes:
    routes: Routes = json.loads((FIXTURES / "org_scenario.json").read_text())
    for route in routes.values():
        body = route.get("body")
        if isinstance(body, dict) and "content_text" in body:
            body["content"] = base64.b64encode(body.pop("content_text").encode()).decode()
    return routes


@pytest.fixture
def routes() -> Routes:
    """Mutable copy of the scenario; tests may override individual paths."""
    return copy.deepcopy(load_scenario())


@pytest.fixture
def requests_seen() -> list[httpx.Request]:
    return []


@pytest.fixture
def github(
    httpx_mock: HTTPXMock, routes: Routes, requests_seen: list[httpx.Request]
) -> Iterator[GitHubContext]:
    def respond(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        body = route.get("body")
        headers = route.get("headers", {})
        if body is None:
            return httpx.Response(route["status"], headers=headers)
        return httpx.Response(route["status"], json=body, headers=headers)

    httpx_mock.add_callback(respond, is_reusable=True, is_optional=True)
    client = GitHubClient("test-token-not-real")
    yield GitHubContext(client=client, org=ORG)
    client.close()


@pytest.fixture
def by_subject() -> Callable[[list[Any]], dict[str, Any]]:
    return lambda findings: {f.subject: f for f in findings}
