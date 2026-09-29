"""Load and validate the control catalog."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentsec.collectors import REGISTRY
from agentsec.models import Catalog


class CatalogError(Exception):
    """Catalog could not be loaded or failed validation."""


def json_schema() -> dict[str, Any]:
    """JSON Schema derived from the pydantic model (source of truth)."""
    return Catalog.model_json_schema()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_catalog(path: Path) -> Catalog:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CatalogError(f"cannot read catalog: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"invalid YAML: {exc}") from exc

    try:
        catalog = Catalog.model_validate(raw)
    except ValidationError as exc:
        raise CatalogError(f"schema validation failed:\n{exc}") from exc

    problems: list[str] = []
    for c in catalog.controls:
        collector = REGISTRY.get(c.collector)
        if collector is None:
            problems.append(f"{c.id}: unknown collector '{c.collector}'")
        elif c.check not in collector.checks:
            problems.append(f"{c.id}: collector '{c.collector}' has no check '{c.check}'")
    if problems:
        raise CatalogError("reference validation failed:\n" + "\n".join(problems))
    return catalog


def write_schema(path: Path) -> None:
    path.write_text(json.dumps(json_schema(), indent=2) + "\n", encoding="utf-8")
