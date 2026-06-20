"""Core data models shared across ghostsbom.

These are plain dataclasses with no third-party dependency so that parsers,
the SBOM builder, the scanner, and the risk engine can exchange data cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# Ecosystem identifiers used internally and mapped to purl / OSV names.
ECOSYSTEM_PYPI = "pypi"
ECOSYSTEM_NPM = "npm"

# Mapping from internal ecosystem id to the OSV.dev ecosystem name.
OSV_ECOSYSTEM = {
    ECOSYSTEM_PYPI: "PyPI",
    ECOSYSTEM_NPM: "npm",
}

# Mapping from internal ecosystem id to the purl type.
PURL_TYPE = {
    ECOSYSTEM_PYPI: "pypi",
    ECOSYSTEM_NPM: "npm",
}


class Severity(str, Enum):
    """Ordered severity levels. Order is meaningful for threshold comparisons."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_ORDER = [
    Severity.NONE,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS base score (0-10) to a qualitative severity bucket."""
    if score <= 0:
        return Severity.NONE
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def severity_from_string(value: str | None) -> Severity:
    """Map a textual severity label (from OSV database_specific) to Severity."""
    if not value:
        return Severity.NONE
    normalized = value.strip().lower()
    table = {
        "none": Severity.NONE,
        "low": Severity.LOW,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "important": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    return table.get(normalized, Severity.NONE)


@dataclass(frozen=True)
class Component:
    """A single resolved dependency."""

    name: str
    version: str
    ecosystem: str

    def purl(self) -> str:
        ptype = PURL_TYPE.get(self.ecosystem, self.ecosystem)
        return f"pkg:{ptype}/{self.name}@{self.version}"

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class Vulnerability:
    """A vulnerability finding mapped onto a component."""

    id: str
    component: Component
    severity: Severity = Severity.NONE
    summary: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    cvss: float | None = None
    aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "component": self.component.key(),
            "severity": self.severity.value,
            "summary": self.summary,
            "fixed_versions": self.fixed_versions,
            "cvss": self.cvss,
            "aliases": self.aliases,
        }


@dataclass
class RiskSignal:
    """A non-CVE supply-chain risk signal."""

    kind: str
    component: Component
    severity: Severity
    message: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "component": self.component.key(),
            "severity": self.severity.value,
            "message": self.message,
            "detail": self.detail,
        }
