# Changelog

All notable changes to this project are documented in this file. The format is
based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.0] - 2026-06-20

Initial release.

### Added
- CycloneDX 1.5 SBOM generation with package URLs (purl) for PyPI and npm.
- Pluggable, filename-auto-detected parsers: Python `requirements.txt`,
  Poetry `poetry.lock` and `pyproject.toml`, and npm `package-lock.json`
  (lockfile versions 1, 2, and 3).
- Vulnerability scanning via the OSV.dev batch API, with severity derived from
  CVSS where present, summaries, and fixed versions mapped onto components.
- Dependency-injected OSV client with timeouts, retries, graceful failure
  handling, and an offline client for `--offline` runs.
- Supply-chain risk signals: Damerau-Levenshtein typosquat detection against a
  bundled top-package list, plus explainable heuristics (immature versions,
  pre-release pins, and an injectable missing-from-registry check).
- Typer-based CLI with `sbom`, `scan`, `audit`, and `version` subcommands,
  rich console tables, JSON report output, and a `--fail-on` CI gate.
- Test suite (pytest) that runs fully offline by mocking all network access.
- Continuous integration running ruff and pytest on Python 3.11 and 3.12.
