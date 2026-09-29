"""Execute catalog checks against a target and aggregate results."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsec import __version__
from agentsec.catalog import sha256_of
from agentsec.collectors import REGISTRY
from agentsec.models import (
    Catalog,
    Finding,
    Report,
    Result,
    RunMetadata,
    Severity,
    Status,
)


def run_catalog(
    catalog: Catalog,
    *,
    target: str,
    org: str,
    context: Any,
    catalog_path: Path,
) -> Report:
    started = datetime.now(UTC)
    spec = REGISTRY[target]
    results: list[Result] = []
    for control in catalog.controls:
        if control.collector != target:
            continue
        check = spec.checks[control.check]
        try:
            findings = check(context, control.params)
        except Exception as exc:  # noqa: BLE001 - any failure must surface as ERROR, never PASS
            findings = [
                Finding(
                    subject=org,
                    status=Status.ERROR,
                    detail=f"check raised {type(exc).__name__}: {exc}",
                )
            ]
        results.append(
            Result(control=control, status=Result.aggregate(findings), findings=findings)
        )
    return Report(
        metadata=RunMetadata(
            tool_version=__version__,
            target=target,
            org=org,
            catalog_path=str(catalog_path),
            catalog_sha256=sha256_of(catalog_path),
            started_at=started,
            finished_at=datetime.now(UTC),
        ),
        results=results,
    )


def exit_code(report: Report, fail_on: Severity) -> int:
    """0 = clean, 1 = FAIL at/above threshold, 2 = ERROR at/above threshold (no FAIL)."""
    relevant = [r for r in report.results if r.control.severity.rank >= fail_on.rank]
    if any(r.status is Status.FAIL for r in relevant):
        return 1
    if any(r.status is Status.ERROR for r in relevant):
        return 2
    return 0
