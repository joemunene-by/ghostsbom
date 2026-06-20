"""ghostsbom command line interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .models import Severity
from .osv import HTTPOSVClient, OfflineOSVClient, OSVClient
from .parsers import parse_file
from .report import Report, render_console
from .risk import assess_risk
from .sbom import build_sbom
from .scanner import scan_components

app = typer.Typer(
    add_completion=False,
    help="Software supply-chain analyzer: SBOM, OSV vulnerability scan, risk signals.",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

_FAIL_ON_CHOICES = [s.value for s in Severity]


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _make_client(offline: bool, timeout: float, retries: int) -> OSVClient:
    if offline:
        return OfflineOSVClient()
    return HTTPOSVClient(timeout=timeout, retries=retries)


def _load_components(manifests: list[Path]):
    components = []
    for manifest in manifests:
        if not manifest.exists():
            err_console.print(f"error: manifest not found: {manifest}", style="red")
            raise typer.Exit(code=2)
        try:
            parsed = parse_file(str(manifest))
        except ValueError as exc:
            err_console.print(f"error: {exc}", style="red")
            raise typer.Exit(code=2) from exc
        components.extend(parsed)
    return components


def _write_json(data: dict, output: Path | None) -> None:
    text = json.dumps(data, indent=2, sort_keys=False)
    if output is None:
        console.print_json(text)
    else:
        output.write_text(text + "\n", encoding="utf-8")
        console.print(f"wrote {output}", style="green")


def _threshold_exit(report: Report, fail_on: str) -> None:
    threshold = Severity(fail_on)
    if threshold == Severity.NONE:
        return
    worst = report.max_severity()
    if worst >= threshold and worst != Severity.NONE:
        err_console.print(
            f"fail-on threshold reached: max severity {worst.value} >= {threshold.value}",
            style="red",
        )
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the ghostsbom version."""
    console.print(f"ghostsbom {__version__}")


@app.command()
def sbom(
    manifests: list[Path] = typer.Argument(..., help="Manifest/lockfile paths."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write CycloneDX JSON here instead of stdout."
    ),
    project_name: str = typer.Option("root", "--name", help="Project name in metadata."),
    project_version: str = typer.Option(
        "0.0.0", "--project-version", help="Project version in metadata."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Generate a CycloneDX 1.5 SBOM from one or more manifests."""
    _configure_logging(verbose)
    components = _load_components(manifests)
    document = build_sbom(
        components, project_name=project_name, project_version=project_version
    )
    _write_json(document, output)


@app.command()
def scan(
    manifests: list[Path] = typer.Argument(..., help="Manifest/lockfile paths."),
    offline: bool = typer.Option(
        False, "--offline", help="Skip network calls; no OSV lookups."
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit non-zero when max severity reaches this threshold "
        f"(one of: {', '.join(_FAIL_ON_CHOICES)}).",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the full JSON report here."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="OSV HTTP timeout (s)."),
    retries: int = typer.Option(3, "--retries", help="OSV HTTP retry count."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Generate an SBOM, scan dependencies via OSV, and add risk signals."""
    if fail_on not in _FAIL_ON_CHOICES:
        err_console.print(
            f"error: --fail-on must be one of {', '.join(_FAIL_ON_CHOICES)}", style="red"
        )
        raise typer.Exit(code=2)

    _configure_logging(verbose)
    components = _load_components(manifests)
    document = build_sbom(components)

    client = _make_client(offline, timeout, retries)
    try:
        vulns = scan_components(components, client)
    except RuntimeError as exc:
        err_console.print(f"error: OSV scan failed: {exc}", style="red")
        raise typer.Exit(code=3) from exc
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()

    risks = assess_risk(components)
    report = Report(
        sbom=document,
        components=components,
        vulnerabilities=vulns,
        risks=risks,
        offline=offline,
    )

    if output is not None:
        _write_json(report.to_dict(), output)
    render_console(report, console)
    _threshold_exit(report, fail_on)


@app.command()
def audit(
    manifests: list[Path] = typer.Argument(..., help="Manifest/lockfile paths."),
    offline: bool = typer.Option(False, "--offline", help="Skip network calls."),
    fail_on: str = typer.Option("none", "--fail-on", help="Severity threshold for exit code."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the full JSON report here."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="OSV HTTP timeout (s)."),
    retries: int = typer.Option(3, "--retries", help="OSV HTTP retry count."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Full audit: SBOM, vulnerabilities, and risk signals as one JSON report.

    Behaves like ``scan`` but always emits the complete machine-readable report
    (to stdout when no --output is given) in addition to the console summary.
    """
    if fail_on not in _FAIL_ON_CHOICES:
        err_console.print(
            f"error: --fail-on must be one of {', '.join(_FAIL_ON_CHOICES)}", style="red"
        )
        raise typer.Exit(code=2)

    _configure_logging(verbose)
    components = _load_components(manifests)
    document = build_sbom(components)

    client = _make_client(offline, timeout, retries)
    try:
        vulns = scan_components(components, client)
    except RuntimeError as exc:
        err_console.print(f"error: OSV scan failed: {exc}", style="red")
        raise typer.Exit(code=3) from exc
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()

    risks = assess_risk(components)
    report = Report(
        sbom=document,
        components=components,
        vulnerabilities=vulns,
        risks=risks,
        offline=offline,
    )

    render_console(report, console)
    _write_json(report.to_dict(), output)
    _threshold_exit(report, fail_on)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
