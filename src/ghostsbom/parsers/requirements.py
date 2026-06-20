"""Parser for Python ``requirements.txt`` files."""

from __future__ import annotations

import re

from ..models import ECOSYSTEM_PYPI, Component
from .base import Parser

# A pinned requirement line: name (with optional extras) == version.
# We deliberately only emit components for exact pins, since SBOMs and OSV
# queries require a concrete version.
_PIN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\s*(?:\[[^\]]*\])?"  # optional extras, e.g. [security]
    r"\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)"
)


def normalize_name(name: str) -> str:
    """Normalize a PyPI project name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


class RequirementsParser(Parser):
    ecosystem = ECOSYSTEM_PYPI
    filename_patterns = ("requirements*.txt", "*requirements.txt")

    def parse(self, text: str) -> list[Component]:
        components: list[Component] = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip inline comments and environment markers / hashes.
            line = line.split(" #", 1)[0].strip()
            line = line.split(";", 1)[0].strip()
            line = line.split("--hash", 1)[0].strip()
            if line.startswith("-"):
                # Options like -r, -e, --index-url. Skipped.
                continue
            match = _PIN_RE.match(line)
            if not match:
                continue
            name = normalize_name(match.group("name"))
            version = match.group("version")
            key = f"{name}=={version}"
            if key in seen:
                continue
            seen.add(key)
            components.append(
                Component(name=name, version=version, ecosystem=self.ecosystem)
            )
        return components
