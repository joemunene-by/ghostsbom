"""CLI and fail-on threshold tests (fully offline)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ghostsbom.cli import app
from ghostsbom.models import ECOSYSTEM_PYPI, Component, RiskSignal, Severity, Vulnerability
from ghostsbom.report import Report
from ghostsbom.sbom import build_sbom

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ghostsbom" in result.stdout


def test_sbom_command(fixtures_dir, tmp_path):
    out = tmp_path / "sbom.json"
    result = runner.invoke(
        app, ["sbom", str(fixtures_dir / "requirements.txt"), "-o", str(out)]
    )
    assert result.exit_code == 0, result.stdout
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert any(c["purl"] == "pkg:pypi/requests@2.19.1" for c in doc["components"])


def test_scan_offline_command(fixtures_dir):
    result = runner.invoke(
        app, ["scan", str(fixtures_dir / "requirements.txt"), "--offline"]
    )
    assert result.exit_code == 0, result.stdout
    # Typosquat 'reqeusts' must surface as a risk signal even offline.
    assert "typosquat" in result.stdout


def test_scan_fail_on_threshold_offline(fixtures_dir):
    # The fixture contains 'reqeusts' (HIGH typosquat). --fail-on high must exit 1.
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "requirements.txt"), "--offline", "--fail-on", "high"],
    )
    assert result.exit_code == 1


def test_scan_fail_on_none_passes(fixtures_dir):
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "requirements.txt"), "--offline", "--fail-on", "none"],
    )
    assert result.exit_code == 0


def test_scan_fail_on_critical_passes_when_only_high(fixtures_dir):
    # Only HIGH present; threshold critical should not trip.
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "requirements.txt"), "--offline", "--fail-on", "critical"],
    )
    assert result.exit_code == 0


def test_invalid_fail_on(fixtures_dir):
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "requirements.txt"), "--offline", "--fail-on", "bogus"],
    )
    assert result.exit_code == 2


def test_missing_manifest():
    result = runner.invoke(app, ["sbom", "/no/such/file.txt"])
    assert result.exit_code == 2


def test_threshold_logic_unit():
    """Directly exercise Report.max_severity used by the threshold gate."""
    comp = Component("x", "1.0.0", ECOSYSTEM_PYPI)
    report = Report(
        sbom=build_sbom([comp]),
        components=[comp],
        vulnerabilities=[
            Vulnerability(id="V1", component=comp, severity=Severity.MEDIUM)
        ],
        risks=[
            RiskSignal(
                kind="typosquat",
                component=comp,
                severity=Severity.CRITICAL,
                message="m",
            )
        ],
    )
    assert report.max_severity() == Severity.CRITICAL
