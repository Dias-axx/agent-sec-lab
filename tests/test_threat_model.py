"""Structural consistency checks for docs/threat-model (acceptance criteria as tests)."""

from __future__ import annotations

import re

import pytest

from .conftest import ROOT

TM = ROOT / "docs" / "threat-model"
ID_RE = re.compile(r"\b([TM]-\d{2})\b")


def _rows(path, prefix):
    rows = {}
    for line in path.read_text().splitlines():
        if line.startswith(f"| {prefix}-"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            assert cells[0] not in rows, f"duplicate id {cells[0]}"
            rows[cells[0]] = cells
    return rows


@pytest.fixture(scope="module")
def threats():
    # ID | Boundary | STRIDE | ATT&CK | Description | L | I | Mitigations | Detection | Residual
    return _rows(TM / "threats.md", "T")


@pytest.fixture(scope="module")
def mitigations():
    # ID | Mitigation | Threats | Type | agentsec
    return _rows(TM / "mitigations.md", "M")


def test_minimum_threat_count(threats):
    assert len(threats) >= 25


def test_threat_rows_complete(threats):
    for tid, c in threats.items():
        assert len(c) == 10, tid
        assert set(c[2].replace(" ", "").split(",")) <= set("STRIDE"), tid
        assert c[5] in "LMH" and c[6] in "LMH" and c[9] in "LMH", tid
        assert c[3], f"{tid}: ATT&CK column empty (use 'no direct mapping')"


def test_high_threats_have_detection(threats):
    for tid, c in threats.items():
        if "H" in (c[5], c[6]):
            assert c[8] and c[8] != "—", f"{tid}: high-rated threat without detection signal"


def test_no_orphans_and_crossrefs_match(threats, mitigations):
    t_to_m = {t: set(ID_RE.findall(c[7])) for t, c in threats.items()}
    m_to_t = {m: set(ID_RE.findall(c[2])) for m, c in mitigations.items()}
    for m, ts in m_to_t.items():
        assert ts, f"{m} references no threat"
        assert ts <= threats.keys(), f"{m} references unknown {ts - threats.keys()}"
    for t, ms in t_to_m.items():
        assert ms, f"{t} has no mitigation"
        assert ms <= mitigations.keys(), f"{t} references unknown {ms - mitigations.keys()}"
        assert ms == {m for m, ts in m_to_t.items() if t in ts}, f"{t}: cross-refs differ"


def test_readme_count_matches(threats):
    assert f"{len(threats)} threats" in (TM / "README.md").read_text()
