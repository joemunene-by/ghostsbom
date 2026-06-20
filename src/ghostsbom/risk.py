"""Supply-chain risk signals: typosquatting and explainable heuristics."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from importlib import resources

from .models import Component, RiskSignal, Severity

logger = logging.getLogger("ghostsbom.risk")


@lru_cache(maxsize=1)
def _popular_packages() -> dict[str, frozenset[str]]:
    """Load the bundled top-package lists, keyed by ecosystem."""
    data_text = (
        resources.files("ghostsbom.data")
        .joinpath("popular_packages.json")
        .read_text(encoding="utf-8")
    )
    raw = json.loads(data_text)
    return {eco: frozenset(names) for eco, names in raw.items()}


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment (restricted Damerau-Levenshtein) distance.

    Counts insertions, deletions, substitutions, and transpositions of two
    adjacent characters. Restricted variant (no substring may be edited twice),
    which is the standard choice for typosquat near-miss detection.
    """
    len_a, len_b = len(a), len(b)
    if len_a == 0:
        return len_b
    if len_b == 0:
        return len_a

    prev_prev = [0] * (len_b + 1)
    prev = list(range(len_b + 1))
    for i in range(1, len_a + 1):
        cur = [i] + [0] * len_b
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(
                cur[j - 1] + 1,  # insertion
                prev[j] + 1,  # deletion
                prev[j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                cur[j] = min(cur[j], prev_prev[j - 2] + 1)  # transposition
        prev_prev, prev = prev, cur
    return prev[len_b]


def detect_typosquat(
    component: Component, *, max_distance: int = 2
) -> RiskSignal | None:
    """Flag a component whose name is a near-miss of a popular package.

    Exact matches are never flagged. A distance of 1-2 against a known popular
    name is reported, with closer matches scored as higher severity.
    """
    popular = _popular_packages().get(component.ecosystem)
    if not popular:
        return None

    name = component.name.lower()
    if name in popular:
        return None

    best_name: str | None = None
    best_distance = max_distance + 1
    for candidate in popular:
        # Skip wildly different lengths quickly.
        if abs(len(candidate) - len(name)) > max_distance:
            continue
        distance = damerau_levenshtein(name, candidate)
        if distance < best_distance:
            best_distance = distance
            best_name = candidate
            if distance == 1:
                break

    if best_name is None or best_distance > max_distance or best_distance == 0:
        return None

    severity = Severity.HIGH if best_distance == 1 else Severity.MEDIUM
    return RiskSignal(
        kind="typosquat",
        component=component,
        severity=severity,
        message=(
            f"name '{component.name}' is within edit distance {best_distance} of "
            f"popular package '{best_name}'"
        ),
        detail={"nearest": best_name, "distance": best_distance},
    )


# Version strings that indicate a placeholder or pre-release / very-new release.
def _looks_prerelease(version: str) -> bool:
    lowered = version.lower()
    return any(
        marker in lowered
        for marker in ("a", "b", "rc", "dev", "alpha", "beta", "pre", "-0")
    ) or lowered.startswith("0.0.")


def detect_heuristics(
    component: Component, *, known_in_registry: bool | None = None
) -> list[RiskSignal]:
    """Explainable, registry-light heuristics.

    ``known_in_registry`` is injected (typically by a registry client behind the
    same offline boundary as OSV), so tests stay offline. ``None`` means unknown
    and no missing-from-registry signal is raised.
    """
    signals: list[RiskSignal] = []
    version = component.version.strip()

    # Very new / zero-ish version: 0.0.x or explicit 0.0.0 placeholder.
    if version.startswith("0.0.") or version in {"0.0.0", "0", "0.0"}:
        signals.append(
            RiskSignal(
                kind="immature_version",
                component=component,
                severity=Severity.LOW,
                message=(
                    f"version '{version}' looks immature (0.0.x); "
                    "verify the package is established"
                ),
                detail={"version": version},
            )
        )
    elif _looks_prerelease(version):
        signals.append(
            RiskSignal(
                kind="prerelease_version",
                component=component,
                severity=Severity.LOW,
                message=f"version '{version}' is a pre-release; not a stable pin",
                detail={"version": version},
            )
        )

    if known_in_registry is False:
        signals.append(
            RiskSignal(
                kind="missing_from_registry",
                component=component,
                severity=Severity.HIGH,
                message=(
                    f"'{component.name}@{component.version}' was not found in the "
                    f"{component.ecosystem} registry; possible withdrawn or fake package"
                ),
                detail={"ecosystem": component.ecosystem},
            )
        )

    return signals


def assess_risk(
    components: list[Component],
    *,
    registry_lookup=None,
    max_distance: int = 2,
) -> list[RiskSignal]:
    """Run all risk signals over ``components``.

    ``registry_lookup`` is an optional callable ``Component -> bool | None`` used
    for the missing-from-registry heuristic. Leaving it ``None`` keeps the run
    fully offline.
    """
    signals: list[RiskSignal] = []
    for component in components:
        squat = detect_typosquat(component, max_distance=max_distance)
        if squat is not None:
            signals.append(squat)

        known: bool | None = None
        if registry_lookup is not None:
            try:
                known = registry_lookup(component)
            except Exception as exc:  # noqa: BLE001 - never fail the whole run
                logger.warning("registry lookup failed for %s: %s", component.name, exc)
                known = None
        signals.extend(detect_heuristics(component, known_in_registry=known))

    signals.sort(key=lambda s: (-s.severity.rank, s.kind, s.component.name))
    return signals
