from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentsec.catalog import CatalogError, json_schema, load_catalog

from .conftest import ROOT

CATALOG = ROOT / "controls" / "catalog.yaml"


def _write(tmp_path: Path, data: object) -> Path:
    p = tmp_path / "catalog.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _base() -> dict:
    return yaml.safe_load(CATALOG.read_text())


def test_repo_catalog_is_valid():
    cat = load_catalog(CATALOG)
    assert len(cat.controls) == 9


def test_committed_schema_matches_models():
    committed = json.loads((ROOT / "controls" / "catalog.schema.json").read_text())
    assert committed == json_schema(), "run `agentsec schema` to regenerate"


def test_duplicate_ids_rejected(tmp_path):
    data = _base()
    data["controls"].append(dict(data["controls"][0]))
    with pytest.raises(CatalogError, match="duplicate"):
        load_catalog(_write(tmp_path, data))


def test_unknown_check_rejected(tmp_path):
    data = _base()
    data["controls"][0]["check"] = "does_not_exist"
    with pytest.raises(CatalogError, match="no check"):
        load_catalog(_write(tmp_path, data))


def test_unknown_collector_rejected(tmp_path):
    data = _base()
    data["controls"][0]["collector"] = "nope"
    with pytest.raises(CatalogError, match="unknown collector"):
        load_catalog(_write(tmp_path, data))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "bad id"),
        ("severity", "urgent"),
        ("evidence", []),
        ("evidence", ["screenshot"]),
        ("frameworks", {}),
        ("unexpected", 1),
    ],
)
def test_schema_violations_rejected(tmp_path, field, value):
    data = _base()
    data["controls"][0][field] = value
    with pytest.raises(CatalogError, match="schema"):
        load_catalog(_write(tmp_path, data))


def test_invalid_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("controls: [unclosed")
    with pytest.raises(CatalogError, match="YAML"):
        load_catalog(p)
