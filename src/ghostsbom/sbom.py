"""CycloneDX 1.5 SBOM generation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from . import __version__
from .models import Component

CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_BOM_FORMAT = "CycloneDX"


def _component_entry(component: Component) -> dict:
    return {
        "type": "library",
        "name": component.name,
        "version": component.version,
        "purl": component.purl(),
        "bom-ref": component.purl(),
    }


def build_sbom(
    components: list[Component],
    *,
    project_name: str = "root",
    project_version: str = "0.0.0",
    timestamp: datetime | None = None,
    serial_number: str | None = None,
) -> dict:
    """Build a CycloneDX 1.5 JSON document from a list of components.

    The ``timestamp`` and ``serial_number`` arguments exist mainly so tests can
    produce deterministic output.
    """
    ts = (timestamp or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = serial_number or f"urn:uuid:{uuid.uuid4()}"

    # De-duplicate components by purl while preserving order.
    seen: set[str] = set()
    entries: list[dict] = []
    for component in components:
        purl = component.purl()
        if purl in seen:
            continue
        seen.add(purl)
        entries.append(_component_entry(component))

    return {
        "bomFormat": CYCLONEDX_BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [
                {
                    "vendor": "joemunene-by",
                    "name": "ghostsbom",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
                "bom-ref": f"root:{project_name}@{project_version}",
            },
        },
        "components": entries,
    }
