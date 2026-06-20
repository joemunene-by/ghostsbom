"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def load_fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def osv_querybatch() -> dict:
    return load_fixture_json("osv_querybatch.json")


@pytest.fixture
def osv_vuln_records() -> dict:
    return {
        "GHSA-x84v-xcm2-53pg": load_fixture_json("osv_vuln_high.json"),
        "GHSA-test-low-0001": load_fixture_json("osv_vuln_low.json"),
    }
