"""GitHub collector: read-only checks against an organisation via the REST API.

Only HTTP GET is ever issued. Every API failure surfaces as an ERROR finding.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from agentsec import __version__
from agentsec.collectors.base import ApiError, CollectorError, CollectorSpec, RateLimitError
from agentsec.models import Evidence, Finding, Status

DEFAULT_BASE_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


class GitHubClient:
    """Minimal read-only GitHub REST client."""

    def __init__(
        self,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        on_response: Callable[[httpx.Response], None] | None = None,
    ) -> None:
        if not token:
            raise CollectorError("GITHUB_TOKEN is empty")
        self._on_response = on_response
        self._http = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": f"agentsec/{__version__}",
            },
        )

    def close(self) -> None:
        self._http.close()

    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> httpx.Response:
        try:
            resp = self._http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise ApiError(path, 0, f"transport error: {type(exc).__name__}") from exc
        if self._on_response is not None:
            self._on_response(resp)
        if resp.status_code in (403, 429) and (
            resp.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in resp.headers
        ):
            reset = resp.headers.get("x-ratelimit-reset", "unknown")
            raise RateLimitError(path, resp.status_code, f"rate limited (reset epoch={reset})")
        return resp

    @staticmethod
    def _message(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return resp.reason_phrase
        if isinstance(body, dict):
            return str(body.get("message", resp.reason_phrase))
        return resp.reason_phrase

    def get_json(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        resp = self._get(path, params)
        if resp.status_code != 200:
            raise ApiError(path, resp.status_code, self._message(resp))
        return resp.json()

    def get_raw(self, path: str) -> tuple[int, Any]:
        """Return (status_code, parsed body or None). Raises only on 5xx / rate limit."""
        resp = self._get(path)
        if resp.status_code >= 500:
            raise ApiError(path, resp.status_code, self._message(resp))
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        return resp.status_code, body

    def get_optional(self, path: str) -> Any | None:
        """GET returning None on 404; other non-200 statuses raise."""
        resp = self._get(path)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise ApiError(path, resp.status_code, self._message(resp))
        return resp.json()

    def paginate(self, path: str, params: Mapping[str, Any] | None = None) -> Iterator[Any]:
        query: dict[str, Any] = {"per_page": 100, **(params or {})}
        next_url: str | None = path
        while next_url:
            resp = self._get(next_url, query if next_url == path else None)
            if resp.status_code != 200:
                raise ApiError(path, resp.status_code, self._message(resp))
            page = resp.json()
            if not isinstance(page, list):
                raise ApiError(path, resp.status_code, "expected a JSON array")
            yield from page
            next_url = resp.links.get("next", {}).get("url")


@dataclass
class GitHubContext:
    client: GitHubClient
    org: str
    include_archived: bool = False
    _repos: list[dict[str, Any]] | None = field(default=None, repr=False)

    def repos(self) -> list[dict[str, Any]]:
        if self._repos is None:
            all_repos = list(self.client.paginate(f"/orgs/{self.org}/repos", {"type": "all"}))
            self._repos = [r for r in all_repos if self.include_archived or not r.get("archived")]
        return self._repos


def _ev(endpoint: str, **excerpt: Any) -> Evidence:
    return Evidence(endpoint=endpoint, excerpt=excerpt)


PLAN_UNAVAILABLE_PREFIX = "Upgrade to GitHub Pro"


def _plan_unavailable(code: int, body: Any) -> bool:
    """403 because the feature is not in the org's plan (e.g. private repo on Free)."""
    return code == 403 and _msg(body).startswith(PLAN_UNAVAILABLE_PREFIX)


def _msg(body: Any) -> str:
    return str(body.get("message", "")) if isinstance(body, dict) else ""


def _err(subject: str, exc: CollectorError) -> Finding:
    return Finding(subject=subject, status=Status.ERROR, detail=str(exc))


def _per_repo(ctx: GitHubContext, fn: Callable[[dict[str, Any]], Finding]) -> list[Finding]:
    repos = ctx.repos()
    if not repos:
        return [
            Finding(
                subject=ctx.org,
                status=Status.ERROR,
                detail="no repositories visible to the token; cannot evaluate",
            )
        ]
    out: list[Finding] = []
    for repo in repos:
        try:
            out.append(fn(repo))
        except CollectorError as exc:
            out.append(_err(repo["full_name"], exc))
    return out


# --------------------------------------------------------------------------- checks


def branch_protection_enabled(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    """Default branch requires PR reviews via classic protection or rulesets."""
    required = int(params.get("required_reviews", 1))

    def one(repo: dict[str, Any]) -> Finding:
        name, branch = repo["full_name"], repo["default_branch"]
        qbranch = quote(branch, safe="")
        evidence: list[Evidence] = []
        plan_limited: list[str] = []

        classic_reviews = 0
        path = f"/repos/{name}/branches/{qbranch}/protection"
        code, body = ctx.client.get_raw(path)
        msg = _msg(body)
        if code == 200:
            prr = body.get("required_pull_request_reviews") or {}
            classic_reviews = int(prr.get("required_approving_review_count", 0))
            evidence.append(_ev(path, required_approving_review_count=classic_reviews))
        elif code == 404 and msg == "Branch not protected":
            evidence.append(_ev(path, status=404, message=msg))
        elif _plan_unavailable(code, body):
            plan_limited.append("classic")
            evidence.append(_ev(path, status=403, plan_unavailable=True))
        else:
            raise ApiError(path, code, msg)

        rules_path = f"/repos/{name}/rules/branches/{qbranch}"
        code, rules = ctx.client.get_raw(rules_path)
        ruleset_reviews = 0
        if code == 200 and isinstance(rules, list):
            ruleset_reviews = max(
                (
                    int((r.get("parameters") or {}).get("required_approving_review_count", 0))
                    for r in rules
                    if r.get("type") == "pull_request"
                ),
                default=0,
            )
            evidence.append(_ev(rules_path, pull_request_required_reviews=ruleset_reviews))
        elif _plan_unavailable(code, rules):
            plan_limited.append("rulesets")
            evidence.append(_ev(rules_path, status=403, plan_unavailable=True))
        else:
            raise ApiError(rules_path, code, _msg(rules))

        effective = max(classic_reviews, ruleset_reviews)
        ok = effective >= required
        detail = f"branch '{branch}': {effective} required review(s), need >= {required}"
        if plan_limited:
            detail += f"; {' and '.join(plan_limited)} not available on current GitHub plan"
        return Finding(
            subject=name,
            status=Status.PASS if ok else Status.FAIL,
            detail=detail,
            evidence=evidence,
        )

    return _per_repo(ctx, one)


def org_mfa_required(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    path = f"/orgs/{ctx.org}"
    try:
        body = ctx.client.get_json(path)
    except CollectorError as exc:
        return [_err(ctx.org, exc)]
    value = body.get("two_factor_requirement_enabled")
    if value is None:
        return [
            Finding(
                subject=ctx.org,
                status=Status.ERROR,
                detail="two_factor_requirement_enabled not visible (requires org owner access)",
                evidence=[_ev(path, two_factor_requirement_enabled=None)],
            )
        ]
    return [
        Finding(
            subject=ctx.org,
            status=Status.PASS if value else Status.FAIL,
            detail=f"2FA requirement enabled: {value}",
            evidence=[_ev(path, two_factor_requirement_enabled=value)],
        )
    ]


def secret_scanning_enabled(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    need_push = bool(params.get("require_push_protection", True))

    def one(repo: dict[str, Any]) -> Finding:
        name = repo["full_name"]
        path = f"/repos/{name}"
        body = ctx.client.get_json(path)
        saa = body.get("security_and_analysis")
        if saa is None:
            return Finding(
                subject=name,
                status=Status.ERROR,
                detail="security_and_analysis not visible (requires admin read)",
                evidence=[_ev(path, security_and_analysis=None)],
            )
        scanning = (saa.get("secret_scanning") or {}).get("status")
        push = (saa.get("secret_scanning_push_protection") or {}).get("status")
        ok = scanning == "enabled" and (push == "enabled" or not need_push)
        return Finding(
            subject=name,
            status=Status.PASS if ok else Status.FAIL,
            detail=f"secret_scanning={scanning}, push_protection={push}",
            evidence=[_ev(path, secret_scanning=scanning, push_protection=push)],
        )

    return _per_repo(ctx, one)


def dependabot_alerts_enabled(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    def one(repo: dict[str, Any]) -> Finding:
        name = repo["full_name"]
        path = f"/repos/{name}/vulnerability-alerts"
        code, body = ctx.client.get_raw(path)
        if code == 204:
            status, detail = Status.PASS, "Dependabot alerts enabled"
        elif code == 404:
            status, detail = Status.FAIL, "Dependabot alerts disabled"
        else:
            raise ApiError(path, code, _msg(body))
        return Finding(
            subject=name, status=status, detail=detail, evidence=[_ev(path, http_status=code)]
        )

    return _per_repo(ctx, one)


def no_public_repos(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    allow = set(params.get("allowlist", []))

    def one(repo: dict[str, Any]) -> Finding:
        name, vis = repo["full_name"], repo.get("visibility")
        if vis is None:
            return Finding(subject=name, status=Status.ERROR, detail="visibility field missing")
        if vis != "public":
            status, detail = Status.PASS, f"visibility={vis}"
        elif repo["name"] in allow:
            status, detail = Status.PASS, "public, allowlisted"
        else:
            status, detail = Status.FAIL, "public and not allowlisted"
        return Finding(
            subject=name,
            status=status,
            detail=detail,
            evidence=[_ev(f"/orgs/{ctx.org}/repos", visibility=vis)],
        )

    return _per_repo(ctx, one)


def _iter_uses(workflow: Any) -> Iterator[str]:
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            yield job["uses"]
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                yield step["uses"]


def is_pinned(uses: str) -> bool:
    """Local actions are fine; docker refs need a digest; everything else a full SHA."""
    if uses.startswith("./"):
        return True
    if uses.startswith("docker://"):
        return "@sha256:" in uses
    _, sep, ref = uses.partition("@")
    return bool(sep) and bool(_SHA_RE.match(ref))


def actions_pinned_shas(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    def one(repo: dict[str, Any]) -> Finding:
        name = repo["full_name"]
        dir_path = f"/repos/{name}/contents/.github/workflows"
        listing = ctx.client.get_optional(dir_path)
        if listing is None:
            return Finding(
                subject=name,
                status=Status.PASS,
                detail="no workflows directory",
                evidence=[_ev(dir_path, http_status=404)],
            )
        unpinned: list[str] = []
        files = [
            f for f in listing if f.get("type") == "file" and f["name"].endswith((".yml", ".yaml"))
        ]
        for f in files:
            fpath = f"/repos/{name}/contents/{f['path']}"
            content = ctx.client.get_json(fpath)
            try:
                text = base64.b64decode(content["content"]).decode("utf-8")
                doc = yaml.safe_load(text)
            except (KeyError, ValueError, yaml.YAMLError) as exc:
                raise CollectorError(f"{f['path']}: cannot parse workflow ({exc})") from exc
            unpinned += [f"{f['path']}: {u}" for u in _iter_uses(doc) if not is_pinned(u)]
        return Finding(
            subject=name,
            status=Status.FAIL if unpinned else Status.PASS,
            detail=(
                f"{len(unpinned)} unpinned action reference(s)"
                if unpinned
                else f"{len(files)} workflow file(s), all references pinned"
            ),
            evidence=[_ev(dir_path, workflow_files=len(files), unpinned=unpinned[:20])],
        )

    return _per_repo(ctx, one)


def actions_default_token_read_only(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    allow_approve = bool(params.get("allow_pr_approval", False))

    def evaluate(subject: str, path: str) -> Finding:
        body = ctx.client.get_json(path)
        perms = body.get("default_workflow_permissions")
        approve = body.get("can_approve_pull_request_reviews")
        ok = perms == "read" and (allow_approve or approve is False)
        return Finding(
            subject=subject,
            status=Status.PASS if ok else Status.FAIL,
            detail=f"default_workflow_permissions={perms}, can_approve_pr_reviews={approve}",
            evidence=[
                _ev(path, default_workflow_permissions=perms, can_approve_pr_reviews=approve)
            ],
        )

    findings: list[Finding] = []
    try:
        findings.append(evaluate(ctx.org, f"/orgs/{ctx.org}/actions/permissions/workflow"))
    except CollectorError as exc:
        findings.append(_err(ctx.org, exc))
    findings += _per_repo(
        ctx,
        lambda r: evaluate(r["full_name"], f"/repos/{r['full_name']}/actions/permissions/workflow"),
    )
    return findings


def codeowners_present(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    def one(repo: dict[str, Any]) -> Finding:
        name = repo["full_name"]
        for rel in CODEOWNERS_PATHS:
            path = f"/repos/{name}/contents/{rel}"
            if ctx.client.get_optional(path) is None:
                continue
            err_path = f"/repos/{name}/codeowners/errors"
            errors = ctx.client.get_json(err_path).get("errors", [])
            return Finding(
                subject=name,
                status=Status.FAIL if errors else Status.PASS,
                detail=f"{rel} present, {len(errors)} syntax error(s)",
                evidence=[_ev(path, found=True), _ev(err_path, error_count=len(errors))],
            )
        return Finding(
            subject=name,
            status=Status.FAIL,
            detail="no CODEOWNERS file in " + ", ".join(CODEOWNERS_PATHS),
            evidence=[_ev(f"/repos/{name}/contents", searched=list(CODEOWNERS_PATHS))],
        )

    return _per_repo(ctx, one)


def org_admin_count(ctx: GitHubContext, params: Mapping[str, Any]) -> list[Finding]:
    max_admins = int(params.get("max_admins", 3))
    min_admins = int(params.get("min_admins", 2))
    path = f"/orgs/{ctx.org}/members"
    try:
        admins = [m["login"] for m in ctx.client.paginate(path, {"role": "admin"})]
    except CollectorError as exc:
        return [_err(ctx.org, exc)]
    n = len(admins)
    ok = min_admins <= n <= max_admins
    return [
        Finding(
            subject=ctx.org,
            status=Status.PASS if ok else Status.FAIL,
            detail=f"{n} org owner(s); allowed range {min_admins}..{max_admins}",
            evidence=[_ev(path, role="admin", count=n)],
        )
    ]


SPEC = CollectorSpec(
    name="github",
    checks={
        "branch_protection_enabled": branch_protection_enabled,
        "org_mfa_required": org_mfa_required,
        "secret_scanning_enabled": secret_scanning_enabled,
        "dependabot_alerts_enabled": dependabot_alerts_enabled,
        "no_public_repos": no_public_repos,
        "actions_pinned_shas": actions_pinned_shas,
        "actions_default_token_read_only": actions_default_token_read_only,
        "codeowners_present": codeowners_present,
        "org_admin_count": org_admin_count,
    },
)
