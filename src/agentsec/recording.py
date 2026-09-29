"""Record live GitHub API responses as test fixtures, and replay fixtures offline.

Fixture format (JSON): ``{"_meta": {...}, "<request path>": {"status", "body", "headers"?}}``.

Recording is read-only (it observes responses of the normal GET-only client) and
minimises every body to the fields the checks read, so recorded fixtures do not carry
tokens, URLs, emails or other unrelated account data. Member logins are pseudonymised.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from agentsec import __version__

Routes = dict[str, dict[str, Any]]
META_KEY = "_meta"

# Fields read by the checks in collectors/github.py. Everything else is dropped.
KEEP_KEYS = frozenset(
    {
        "actor_type",
        "archived",
        "bypass_actors",
        "bypass_mode",
        "can_approve_pull_request_reviews",
        "content",
        "default_branch",
        "default_workflow_permissions",
        "enabled",
        "encoding",
        "enforce_admins",
        "errors",
        "full_name",
        "kind",
        "line",
        "login",
        "message",
        "name",
        "parameters",
        "path",
        "required_approving_review_count",
        "required_pull_request_reviews",
        "ruleset_id",
        "secret_scanning",
        "secret_scanning_push_protection",
        "security_and_analysis",
        "status",
        "two_factor_requirement_enabled",
        "type",
        "visibility",
    }
)
KEEP_HEADERS = ("retry-after", "x-ratelimit-remaining", "x-ratelimit-reset")


def minimize(obj: Any) -> Any:
    """Recursively keep only KEEP_KEYS in dicts."""
    if isinstance(obj, dict):
        return {k: minimize(v) for k, v in obj.items() if k in KEEP_KEYS}
    if isinstance(obj, list):
        return [minimize(v) for v in obj]
    return obj


class Recorder:
    """Collects minimised responses keyed by request path. Use as GitHubClient.on_response."""

    def __init__(
        self, org: str, *, org_alias: str | None = None, pseudonymize_logins: bool = True
    ) -> None:
        self.org = org
        self.alias = org_alias or org
        self.pseudonymize_logins = pseudonymize_logins
        self.routes: Routes = {}
        self._logins: dict[str, str] = {}

    def _rename(self, value: str) -> str:
        if self.alias == self.org:
            return value
        org, alias = self.org, self.alias
        if value == org:
            return alias
        if value.startswith(f"{org}/"):  # full_name
            value = alias + value[len(org) :]
        if value.endswith(f"/{org}"):  # /orgs/<org>
            value = value[: -len(org)] + alias
        return value.replace(f"/{org}/", f"/{alias}/")

    def _scrub(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                if k == "login" and isinstance(v, str) and v != self.org:
                    v = self._pseudonym(v) if self.pseudonymize_logins else v
                out[k] = self._scrub(v)
            return out
        if isinstance(obj, list):
            return [self._scrub(v) for v in obj]
        if isinstance(obj, str):
            return self._rename(obj)
        return obj

    def _pseudonym(self, login: str) -> str:
        return self._logins.setdefault(login, f"user-{len(self._logins) + 1}")

    def __call__(self, resp: httpx.Response) -> None:
        req = resp.request
        if req.method != "GET":  # defensive: the client never sends anything else
            return
        resp.read()
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        body = self._scrub(minimize(body))
        key = self._rename(req.url.path)
        page = int(req.url.params.get("page", "1") or 1)
        existing = self.routes.get(key)
        if (
            page > 1
            and existing
            and isinstance(existing.get("body"), list)
            and isinstance(body, list)
        ):
            existing["body"].extend(body)  # merge pagination; replay ignores query strings
            return
        route: dict[str, Any] = {"status": resp.status_code, "body": body}
        headers = {h: resp.headers[h] for h in KEEP_HEADERS if h in resp.headers}
        if headers and resp.status_code in (403, 429):
            route["headers"] = headers
        self.routes[key] = route

    def document(self, *, api_url: str) -> dict[str, Any]:
        meta = {
            "kind": "recorded",
            "org": self.alias,
            "recorded_at": datetime.now(UTC).isoformat(),
            "tool_version": __version__,
            "api_url": api_url,
            "note": "Recorded from a live API; bodies minimised, logins pseudonymised.",
        }
        return {META_KEY: meta, **dict(sorted(self.routes.items()))}

    def save(self, path: Path, *, api_url: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.document(api_url=api_url), indent=2) + "\n", "utf-8")
        return path


def parse_fixture(raw: dict[str, Any]) -> tuple[dict[str, Any], Routes]:
    """Return (meta, routes). A body key ``content_text`` is base64-encoded into ``content``."""
    raw = dict(raw)
    meta = raw.pop(META_KEY, {"kind": "unknown"})
    for route in raw.values():
        body = route.get("body")
        if isinstance(body, dict) and "content_text" in body:
            body["content"] = base64.b64encode(body.pop("content_text").encode()).decode()
    return meta, raw


def load_fixture(path: Path) -> tuple[dict[str, Any], Routes]:
    return parse_fixture(json.loads(path.read_text(encoding="utf-8")))


def replay_transport(routes: Routes, *, strict: bool = True) -> httpx.MockTransport:
    """Serve fixture routes by path. Unknown paths: strict → 501 (→ ERROR), else 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            return httpx.Response(405, json={"message": "replay is read-only"})
        route = routes.get(request.url.path)
        if route is None:
            if strict:
                return httpx.Response(501, json={"message": "path not in fixture"})
            return httpx.Response(404, json={"message": "Not Found"})
        headers = route.get("headers", {})
        if route.get("body") is None:
            return httpx.Response(route["status"], headers=headers)
        return httpx.Response(route["status"], json=route["body"], headers=headers)

    return httpx.MockTransport(handler)
