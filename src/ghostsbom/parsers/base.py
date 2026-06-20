"""Parser protocol."""

from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod

from ..models import Component


class Parser(ABC):
    """Base class for manifest parsers.

    A parser declares the ecosystem it produces, the filename patterns it
    recognises, and how to turn raw manifest text into components.
    """

    #: Internal ecosystem id (see models.ECOSYSTEM_*).
    ecosystem: str = ""

    #: Glob patterns matched case-insensitively against the basename.
    filename_patterns: tuple[str, ...] = ()

    def matches(self, filename: str) -> bool:
        lowered = filename.lower()
        return any(fnmatch.fnmatch(lowered, pat) for pat in self.filename_patterns)

    @abstractmethod
    def parse(self, text: str) -> list[Component]:
        """Parse raw manifest text into a list of components."""
        raise NotImplementedError
