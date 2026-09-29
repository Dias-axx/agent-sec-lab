"""Core data models: Control, Evidence, Finding, Result, Report."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Status(StrEnum):
    PASS = "PASS"  # noqa: S105 - status label, not a credential
    FAIL = "FAIL"
    ERROR = "ERROR"


class EvidenceKind(StrEnum):
    API_RESPONSE_EXCERPT = "api_response_excerpt"
    TIMESTAMP = "timestamp"
    REPO = "repo"
    ORG = "org"
    ENDPOINT = "endpoint"


class Frameworks(BaseModel):
    """Informal mapping to framework criteria. IDs only, no framework text."""

    model_config = ConfigDict(extra="forbid")

    soc2: list[str] = Field(default_factory=list, description="SOC 2 TSC criterion IDs")
    iso27001: list[str] = Field(
        default_factory=list, description="ISO/IEC 27001:2022 Annex A control IDs"
    )


class Control(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z]{2,4}-\d{2}$")
    title: str = Field(min_length=3)
    frameworks: Frameworks
    severity: Severity
    collector: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    check: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    params: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceKind] = Field(min_length=1)
    remediation: str = Field(min_length=3)

    @field_validator("frameworks")
    @classmethod
    def _at_least_one_mapping(cls, v: Frameworks) -> Frameworks:
        if not v.soc2 and not v.iso27001:
            raise ValueError("control must map to at least one framework criterion")
        return v


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    controls: list[Control] = Field(min_length=1)

    @field_validator("controls")
    @classmethod
    def _unique_ids(cls, v: list[Control]) -> list[Control]:
        seen: set[str] = set()
        dupes: set[str] = set()
        for c in v:
            (dupes if c.id in seen else seen).add(c.id)
        if dupes:
            raise ValueError(f"duplicate control ids: {sorted(dupes)}")
        return v


class Evidence(BaseModel):
    """Evidence captured for one subject (org or repo). Never contains credentials."""

    endpoint: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    excerpt: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Outcome of a check for one subject (e.g. one repo, or the org)."""

    subject: str
    status: Status
    detail: str
    evidence: list[Evidence] = Field(default_factory=list)


class Result(BaseModel):
    """Aggregated outcome for one control."""

    control: Control
    status: Status
    findings: list[Finding] = Field(default_factory=list)

    @staticmethod
    def aggregate(findings: list[Finding]) -> Status:
        """FAIL dominates, then ERROR. No findings is ERROR (never a silent pass)."""
        if not findings:
            return Status.ERROR
        statuses = {f.status for f in findings}
        if Status.FAIL in statuses:
            return Status.FAIL
        if Status.ERROR in statuses:
            return Status.ERROR
        return Status.PASS


class RunMetadata(BaseModel):
    tool_version: str
    target: str
    org: str
    catalog_path: str
    catalog_sha256: str
    started_at: datetime
    finished_at: datetime


class Report(BaseModel):
    metadata: RunMetadata
    results: list[Result]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for r in self.results:
            out[r.status.value] += 1
        return out
