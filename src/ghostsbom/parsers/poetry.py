"""Parser for Poetry manifests: ``poetry.lock`` and ``pyproject.toml``.

``poetry.lock`` is preferred because it carries resolved versions for the full
dependency graph. ``pyproject.toml`` is parsed as a fallback for the direct
dependencies declared under ``[tool.poetry.dependencies]`` (only exact pins).
"""

from __future__ import annotations

import tomllib

from ..models import ECOSYSTEM_PYPI, Component
from .base import Parser
from .requirements import normalize_name


def _clean_pin(spec: str) -> str | None:
    """Return a concrete version from a simple pin like ``2.0.0`` or ``==2.0.0``."""
    spec = spec.strip()
    if spec.startswith("=="):
        spec = spec[2:].strip()
    # Reject ranges / carets / wildcards which have no single resolved version.
    if any(ch in spec for ch in "^~*<>! ,"):
        return None
    if not spec or spec[0].isalpha() and not spec[0].isdigit():
        # Allow versions that begin with a digit; reject pure markers.
        pass
    if spec[:1].isdigit():
        return spec
    return None


class PoetryParser(Parser):
    ecosystem = ECOSYSTEM_PYPI
    filename_patterns = ("poetry.lock", "pyproject.toml")

    def parse(self, text: str) -> list[Component]:
        data = tomllib.loads(text)
        if "package" in data and isinstance(data["package"], list):
            return self._parse_lock(data)
        return self._parse_pyproject(data)

    def _parse_lock(self, data: dict) -> list[Component]:
        components: list[Component] = []
        seen: set[str] = set()
        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            name = normalize_name(str(name))
            key = f"{name}=={version}"
            if key in seen:
                continue
            seen.add(key)
            components.append(
                Component(name=name, version=str(version), ecosystem=self.ecosystem)
            )
        return components

    def _parse_pyproject(self, data: dict) -> list[Component]:
        components: list[Component] = []
        seen: set[str] = set()
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        for name, spec in deps.items():
            if name.lower() == "python":
                continue
            version: str | None = None
            if isinstance(spec, str):
                version = _clean_pin(spec)
            elif isinstance(spec, dict):
                raw = spec.get("version")
                if isinstance(raw, str):
                    version = _clean_pin(raw)
            if not version:
                continue
            norm = normalize_name(name)
            key = f"{norm}=={version}"
            if key in seen:
                continue
            seen.add(key)
            components.append(
                Component(name=norm, version=version, ecosystem=self.ecosystem)
            )
        return components
