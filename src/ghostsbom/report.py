"""Report assembly and rich rendering."""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from . import __version__
from .models import Component, RiskSignal, Severity, Vulnerability

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.NONE: "dim",
}


@dataclass
class Report:
    """The full audit result."""

    sbom: dict
    components: list[Component]
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    risks: list[RiskSignal] = field(default_factory=list)
    offline: bool = False

    def to_dict(self) -> dict:
        return {
            "tool": "ghostsbom",
            "version": __version__,
            "offline": self.offline,
            "summary": {
                "components": len(self.components),
                "vulnerabilities": len(self.vulnerabilities),
                "risk_signals": len(self.risks),
                "max_severity": self.max_severity().value,
            },
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "ecosystem": c.ecosystem,
                    "purl": c.purl(),
                }
                for c in self.components
            ],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_signals": [r.to_dict() for r in self.risks],
            "sbom": self.sbom,
        }

    def max_severity(self) -> Severity:
        worst = Severity.NONE
        for item in (*self.vulnerabilities, *self.risks):
            if item.severity > worst:
                worst = item.severity
        return worst


def _sev_text(severity: Severity) -> str:
    style = _SEVERITY_STYLE.get(severity, "dim")
    return f"[{style}]{severity.value.upper()}[/{style}]"


def render_console(report: Report, console: Console | None = None) -> None:
    """Render a human-readable summary to the console."""
    console = console or Console()

    console.print(
        f"[bold]ghostsbom[/bold] {__version__}  "
        f"components={len(report.components)}  "
        f"vulns={len(report.vulnerabilities)}  "
        f"risks={len(report.risks)}  "
        f"offline={'yes' if report.offline else 'no'}"
    )

    if report.vulnerabilities:
        vuln_table = Table(title="Vulnerabilities", show_lines=False, expand=True)
        vuln_table.add_column("Severity", no_wrap=True)
        vuln_table.add_column("Package", no_wrap=True)
        vuln_table.add_column("ID", no_wrap=True)
        vuln_table.add_column("Fixed in", no_wrap=True)
        vuln_table.add_column("Summary")
        for vuln in report.vulnerabilities:
            vuln_table.add_row(
                _sev_text(vuln.severity),
                f"{vuln.component.name}@{vuln.component.version}",
                vuln.id,
                ", ".join(vuln.fixed_versions) or "-",
                vuln.summary or "-",
            )
        console.print(vuln_table)
    else:
        console.print("No known vulnerabilities reported.", style="green")

    if report.risks:
        risk_table = Table(title="Risk signals", show_lines=False, expand=True)
        risk_table.add_column("Severity", no_wrap=True)
        risk_table.add_column("Kind", no_wrap=True)
        risk_table.add_column("Package", no_wrap=True)
        risk_table.add_column("Detail")
        for risk in report.risks:
            risk_table.add_row(
                _sev_text(risk.severity),
                risk.kind,
                f"{risk.component.name}@{risk.component.version}",
                risk.message,
            )
        console.print(risk_table)
    else:
        console.print("No supply-chain risk signals raised.", style="green")

    console.print(
        f"Highest severity: {_sev_text(report.max_severity())}"
    )
