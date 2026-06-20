"""Parser for npm ``package-lock.json`` (lockfile v1, v2, and v3)."""

from __future__ import annotations

import json

from ..models import ECOSYSTEM_NPM, Component
from .base import Parser


def _name_from_path(path: str) -> str | None:
    """Derive a package name from a ``node_modules`` path key (lockfile v2/v3).

    Example: ``node_modules/@scope/pkg/node_modules/lodash`` -> ``lodash``.
    """
    if "node_modules/" not in path:
        return None
    tail = path.rsplit("node_modules/", 1)[1]
    if not tail:
        return None
    parts = tail.split("/")
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


class PackageLockParser(Parser):
    ecosystem = ECOSYSTEM_NPM
    filename_patterns = ("package-lock.json", "npm-shrinkwrap.json")

    def parse(self, text: str) -> list[Component]:
        data = json.loads(text)
        components: list[Component] = []
        seen: set[str] = set()

        def add(name: str | None, version: str | None) -> None:
            if not name or not version:
                return
            key = f"{name}@{version}"
            if key in seen:
                return
            seen.add(key)
            components.append(
                Component(name=name, version=str(version), ecosystem=self.ecosystem)
            )

        # Lockfile v2/v3: the "packages" map keyed by install path.
        packages = data.get("packages")
        if isinstance(packages, dict):
            for path, meta in packages.items():
                if path == "":
                    # The root project entry; not a dependency.
                    continue
                if not isinstance(meta, dict):
                    continue
                name = meta.get("name") or _name_from_path(path)
                add(name, meta.get("version"))

        # Lockfile v1: the nested "dependencies" tree keyed by name.
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            _walk_v1(deps, add)

        return components


def _walk_v1(deps: dict, add) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        add(name, meta.get("version"))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(nested, add)
