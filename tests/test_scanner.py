"""Vulnerability scanner tests with a mocked OSV client."""

from __future__ import annotations

import pytest

from ghostsbom.models import ECOSYSTEM_PYPI, Component, Severity
from ghostsbom.osv import OfflineOSVClient
from ghostsbom.scanner import max_severity, scan_components


class FakeOSVClient:
    """Mocked OSV client returning canned data; no network involved."""

    def __init__(self, batch, records):
        self._batch = batch
        self._records = records
        self.batch_calls = 0
        self.vuln_calls = []

    def query_batch(self, components):
        self.batch_calls += 1
        # Map fixture's positional results onto component keys.
        results = self._batch["results"]
        mapping = {}
        for component, result in zip(components, results, strict=False):
            ids = [v["id"] for v in result.get("vulns", [])]
            mapping[component.key()] = ids
        return mapping

    def get_vuln(self, vuln_id):
        self.vuln_calls.append(vuln_id)
        return self._records[vuln_id]


def _components():
    return [
        Component("urllib3", "1.24.1", ECOSYSTEM_PYPI),
        Component("flask", "2.0.0", ECOSYSTEM_PYPI),
        Component("requests", "2.19.1", ECOSYSTEM_PYPI),
    ]


def test_scan_maps_severity_and_fixes(osv_querybatch, osv_vuln_records):
    client = FakeOSVClient(osv_querybatch, osv_vuln_records)
    vulns = scan_components(_components(), client)

    assert client.batch_calls == 1
    assert len(vulns) == 2

    by_id = {v.id: v for v in vulns}
    high = by_id["GHSA-x84v-xcm2-53pg"]
    assert high.component.name == "urllib3"
    assert high.severity == Severity.HIGH
    assert high.cvss == 7.5
    assert "1.24.2" in high.fixed_versions
    assert "CVE-2018-20060" in high.aliases

    low = by_id["GHSA-test-low-0001"]
    assert low.component.name == "flask"
    assert low.severity == Severity.LOW
    assert "2.0.1" in low.fixed_versions

    # Sorted by severity descending: HIGH before LOW.
    assert vulns[0].severity == Severity.HIGH
    assert vulns[1].severity == Severity.LOW


def test_scan_offline_returns_nothing():
    vulns = scan_components(_components(), OfflineOSVClient())
    assert vulns == []


def test_scan_empty_components():
    client = FakeOSVClient({"results": []}, {})
    assert scan_components([], client) == []
    assert client.batch_calls == 0


def test_max_severity_combines():
    record = {"id": "GHSA-test-low-0001", "database_specific": {"severity": "LOW"}}
    client = FakeOSVClient(
        {"results": [{"vulns": [{"id": "GHSA-test-low-0001"}]}, {}, {}]},
        {"GHSA-test-low-0001": record},
    )
    vulns = scan_components(_components(), client)
    assert max_severity(vulns) == Severity.LOW


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, Severity.NONE),
        (3.9, Severity.LOW),
        (5.0, Severity.MEDIUM),
        (7.5, Severity.HIGH),
        (9.8, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss(score, expected):
    from ghostsbom.models import severity_from_cvss

    assert severity_from_cvss(score) == expected
