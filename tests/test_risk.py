"""Risk-signal tests: typosquat and heuristics."""

from __future__ import annotations

from ghostsbom.models import ECOSYSTEM_NPM, ECOSYSTEM_PYPI, Component, Severity
from ghostsbom.risk import (
    assess_risk,
    damerau_levenshtein,
    detect_heuristics,
    detect_typosquat,
)


def test_damerau_levenshtein_basics():
    assert damerau_levenshtein("requests", "requests") == 0
    assert damerau_levenshtein("reqeusts", "requests") == 1  # transposition
    assert damerau_levenshtein("requsts", "requests") == 1  # deletion
    assert damerau_levenshtein("", "abc") == 3


def test_typosquat_flags_obvious_squat():
    squat = Component("reqeusts", "2.19.1", ECOSYSTEM_PYPI)
    signal = detect_typosquat(squat)
    assert signal is not None
    assert signal.kind == "typosquat"
    assert signal.detail["nearest"] == "requests"
    assert signal.detail["distance"] == 1
    assert signal.severity == Severity.HIGH


def test_typosquat_does_not_flag_legit():
    legit = Component("requests", "2.31.0", ECOSYSTEM_PYPI)
    assert detect_typosquat(legit) is None


def test_typosquat_does_not_flag_distant_name():
    # A name far from anything popular should not be flagged.
    obscure = Component("zzzqwertyxyz", "1.0.0", ECOSYSTEM_PYPI)
    assert detect_typosquat(obscure) is None


def test_typosquat_npm():
    squat = Component("expres", "4.16.0", ECOSYSTEM_NPM)
    signal = detect_typosquat(squat)
    assert signal is not None
    assert signal.detail["nearest"] == "express"


def test_heuristic_immature_version():
    comp = Component("somepkg", "0.0.1", ECOSYSTEM_PYPI)
    signals = detect_heuristics(comp)
    kinds = {s.kind for s in signals}
    assert "immature_version" in kinds


def test_heuristic_prerelease_version():
    comp = Component("somepkg", "1.0.0rc1", ECOSYSTEM_PYPI)
    signals = detect_heuristics(comp)
    kinds = {s.kind for s in signals}
    assert "prerelease_version" in kinds


def test_heuristic_missing_from_registry():
    comp = Component("ghostpkg", "1.0.0", ECOSYSTEM_PYPI)
    signals = detect_heuristics(comp, known_in_registry=False)
    kinds = {s.kind for s in signals}
    assert "missing_from_registry" in kinds
    missing = next(s for s in signals if s.kind == "missing_from_registry")
    assert missing.severity == Severity.HIGH


def test_heuristic_known_registry_no_signal():
    comp = Component("requests", "2.31.0", ECOSYSTEM_PYPI)
    signals = detect_heuristics(comp, known_in_registry=True)
    assert all(s.kind != "missing_from_registry" for s in signals)


def test_assess_risk_offline_and_sorted():
    components = [
        Component("requests", "2.31.0", ECOSYSTEM_PYPI),  # legit, no signal
        Component("reqeusts", "2.19.1", ECOSYSTEM_PYPI),  # typosquat HIGH
        Component("somepkg", "0.0.1", ECOSYSTEM_PYPI),  # immature LOW
    ]
    signals = assess_risk(components)
    kinds = {s.kind for s in signals}
    assert "typosquat" in kinds
    assert "immature_version" in kinds
    # Sorted highest severity first.
    assert signals[0].severity >= signals[-1].severity


def test_assess_risk_registry_lookup_injection():
    components = [Component("ghostpkg", "1.0.0", ECOSYSTEM_PYPI)]
    signals = assess_risk(components, registry_lookup=lambda c: False)
    assert any(s.kind == "missing_from_registry" for s in signals)
