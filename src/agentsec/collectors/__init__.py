"""Collector registry. Maps catalog `collector` names to their checks."""

from __future__ import annotations

from agentsec.collectors import github
from agentsec.collectors.base import CollectorSpec

REGISTRY: dict[str, CollectorSpec] = {
    github.SPEC.name: github.SPEC,
}

__all__ = ["REGISTRY", "CollectorSpec"]
