"""Collector primitives shared by all targets."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from agentsec.models import Finding

CheckFn = Callable[[Any, Mapping[str, Any]], list[Finding]]


class CollectorError(Exception):
    """Evidence could not be collected. Always maps to status ERROR, never PASS."""


class ApiError(CollectorError):
    def __init__(self, endpoint: str, status: int, message: str) -> None:
        super().__init__(f"{endpoint}: HTTP {status}: {message}")
        self.endpoint = endpoint
        self.status = status
        self.message = message


class RateLimitError(ApiError):
    """API rate limit hit. Reported as ERROR; the tool does not sleep/retry silently."""


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    checks: Mapping[str, CheckFn]
