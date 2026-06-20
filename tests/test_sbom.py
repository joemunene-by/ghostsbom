"""CycloneDX SBOM structure tests."""

from __future__ import annotations

from datetime import UTC

from ghostsbom.models import ECOSYSTEM_NPM, ECOSYSTEM_PYPI, Component
from ghostsbom.sbom import build_sbom


def _sample_components():
    return [
        Component("requests", "2.19.1", ECOSYSTEM_PYPI),
        Component("lodash", "4.17.4", ECOSYSTEM_NPM),
    ]


def test_sbom_required_fields():
    doc = build_sbom(_sample_components(), project_name="demo", project_version="1.2.3")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["version"] == 1
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert "timestamp" in doc["metadata"]
    assert doc["metadata"]["component"]["name"] == "demo"
    assert doc["metadata"]["tools"][0]["name"] == "ghostsbom"


def test_sbom_purls():
    doc = build_sbom(_sample_components())
    purls = {c["purl"] for c in doc["components"]}
    assert "pkg:pypi/requests@2.19.1" in purls
    assert "pkg:npm/lodash@4.17.4" in purls
    for entry in doc["components"]:
        assert entry["type"] == "library"
        assert entry["name"]
        assert entry["version"]
        assert entry["purl"].startswith("pkg:")
        assert entry["bom-ref"] == entry["purl"]


def test_sbom_deduplicates():
    components = _sample_components() + [Component("requests", "2.19.1", ECOSYSTEM_PYPI)]
    doc = build_sbom(components)
    assert len(doc["components"]) == 2


def test_sbom_deterministic_with_overrides():
    from datetime import datetime

    ts = datetime(2026, 1, 1, tzinfo=UTC)
    doc = build_sbom(
        _sample_components(),
        timestamp=ts,
        serial_number="urn:uuid:00000000-0000-0000-0000-000000000000",
    )
    assert doc["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"
    assert doc["serialNumber"] == "urn:uuid:00000000-0000-0000-0000-000000000000"
