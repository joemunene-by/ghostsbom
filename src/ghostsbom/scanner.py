"""Vulnerability scanner that maps OSV records onto components."""

from __future__ import annotations

import logging

from .models import (
    Component,
    Severity,
    Vulnerability,
    severity_from_cvss,
    severity_from_string,
)
from .osv import OSVClient

logger = logging.getLogger("ghostsbom.scanner")

# Minimal CVSS v3 base-score extraction. We parse the AV/AC/.../A vector and
# would normally compute a score, but OSV usually ships an explicit score in the
# vector string suffix or in database_specific. To stay dependency-free and
# explainable we read the score from database_specific first, then fall back to
# the qualitative severity label.


def _extract_cvss_score(record: dict) -> float | None:
    """Pull a numeric CVSS base score from an OSV record if present."""
    severities = record.get("severity") or []
    for entry in severities:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        # Some OSV records carry a plain numeric string in "score".
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                continue
    db = record.get("database_specific") or {}
    raw = db.get("cvss_score") or db.get("cvss")
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError:
            return None
    return None


def _extract_label(record: dict) -> str | None:
    db = record.get("database_specific") or {}
    label = db.get("severity")
    if isinstance(label, str):
        return label
    return None


def _fixed_versions(record: dict, component: Component) -> list[str]:
    """Collect 'fixed' versions from the OSV affected ranges for this package."""
    fixes: list[str] = []
    for affected in record.get("affected", []):
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package", {})
        if pkg.get("name") and pkg["name"].lower() != component.name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in fixes:
                    fixes.append(fixed)
    return fixes


def _build_vulnerability(record: dict, component: Component) -> Vulnerability:
    vuln_id = record.get("id", "UNKNOWN")
    summary = record.get("summary") or record.get("details", "")
    if summary:
        summary = summary.strip().splitlines()[0][:300]

    cvss = _extract_cvss_score(record)
    if cvss is not None:
        severity = severity_from_cvss(cvss)
    else:
        severity = severity_from_string(_extract_label(record))

    return Vulnerability(
        id=vuln_id,
        component=component,
        severity=severity,
        summary=summary,
        fixed_versions=_fixed_versions(record, component),
        cvss=cvss,
        aliases=list(record.get("aliases", [])),
    )


def scan_components(
    components: list[Component], client: OSVClient
) -> list[Vulnerability]:
    """Query OSV for ``components`` via ``client`` and return findings.

    Network and offline behaviour live entirely behind ``client``; this function
    is pure mapping logic and is fully exercised by tests with a fake client.
    """
    if not components:
        return []

    by_key = {c.key(): c for c in components}
    mapping = client.query_batch(components)

    findings: list[Vulnerability] = []
    for key, vuln_ids in mapping.items():
        component = by_key.get(key)
        if component is None or not vuln_ids:
            continue
        for vuln_id in vuln_ids:
            try:
                record = client.get_vuln(vuln_id)
            except Exception as exc:  # noqa: BLE001 - log and continue scanning
                logger.warning("failed to fetch %s: %s", vuln_id, exc)
                record = {"id": vuln_id}
            findings.append(_build_vulnerability(record, component))

    findings.sort(key=lambda v: (-v.severity.rank, v.component.name, v.id))
    return findings


def max_severity(
    vulns: list[Vulnerability], signals: list | None = None
) -> Severity:
    """Return the highest severity across vulnerabilities and risk signals."""
    worst = Severity.NONE
    for vuln in vulns:
        if vuln.severity > worst:
            worst = vuln.severity
    for signal in signals or []:
        if signal.severity > worst:
            worst = signal.severity
    return worst
