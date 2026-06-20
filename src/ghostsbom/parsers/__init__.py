"""Pluggable manifest parsers, dispatched by filename."""

from __future__ import annotations

import os

from ..models import Component
from .base import Parser
from .npm_lock import PackageLockParser
from .poetry import PoetryParser
from .requirements import RequirementsParser

# Registration order matters only when several parsers could match; the first
# parser whose ``matches`` returns True wins.
PARSERS: list[Parser] = [
    RequirementsParser(),
    PoetryParser(),
    PackageLockParser(),
]

__all__ = [
    "Parser",
    "RequirementsParser",
    "PoetryParser",
    "PackageLockParser",
    "PARSERS",
    "parser_for",
    "parse_file",
]


def parser_for(path: str) -> Parser | None:
    """Return the first parser that recognises ``path`` by filename, else None."""
    filename = os.path.basename(path)
    for parser in PARSERS:
        if parser.matches(filename):
            return parser
    return None


def parse_file(path: str) -> list[Component]:
    """Auto-detect the manifest type from ``path`` and parse it.

    Raises ``ValueError`` if no parser recognises the file.
    """
    parser = parser_for(path)
    if parser is None:
        raise ValueError(f"no parser recognises manifest: {os.path.basename(path)}")
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    return parser.parse(text)
