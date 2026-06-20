"""Parser tests against fixture manifests."""

from __future__ import annotations

from ghostsbom.models import ECOSYSTEM_NPM, ECOSYSTEM_PYPI
from ghostsbom.parsers import parse_file, parser_for
from ghostsbom.parsers.npm_lock import PackageLockParser
from ghostsbom.parsers.poetry import PoetryParser
from ghostsbom.parsers.requirements import RequirementsParser


def _as_set(components):
    return {(c.name, c.version, c.ecosystem) for c in components}


def test_parser_autodetect(fixtures_dir):
    assert isinstance(parser_for(str(fixtures_dir / "requirements.txt")), RequirementsParser)
    assert isinstance(parser_for(str(fixtures_dir / "poetry.lock")), PoetryParser)
    assert isinstance(parser_for(str(fixtures_dir / "package-lock.json")), PackageLockParser)
    assert parser_for("Gemfile.lock") is None


def test_requirements_parser(fixtures_dir):
    components = parse_file(str(fixtures_dir / "requirements.txt"))
    got = _as_set(components)
    assert ("requests", "2.19.1", ECOSYSTEM_PYPI) in got
    assert ("urllib3", "1.24.1", ECOSYSTEM_PYPI) in got
    assert ("flask", "2.0.0", ECOSYSTEM_PYPI) in got
    assert ("pyyaml", "5.3.1", ECOSYSTEM_PYPI) in got
    # Normalized name and the typosquat both present.
    assert ("reqeusts", "2.19.1", ECOSYSTEM_PYPI) in got
    # Hash and inline marker handled.
    assert ("six", "1.16.0", ECOSYSTEM_PYPI) in got
    # Unpinned line and -r include are skipped.
    names = {c.name for c in components}
    assert "black" not in names
    assert all(not c.name.startswith("-") for c in components)


def test_poetry_lock_parser(fixtures_dir):
    components = parse_file(str(fixtures_dir / "poetry.lock"))
    got = _as_set(components)
    assert ("requests", "2.19.1", ECOSYSTEM_PYPI) in got
    assert ("urllib3", "1.24.1", ECOSYSTEM_PYPI) in got
    assert ("flask", "2.0.0", ECOSYSTEM_PYPI) in got
    assert len(components) == 3


def test_npm_lock_parser(fixtures_dir):
    components = parse_file(str(fixtures_dir / "package-lock.json"))
    got = _as_set(components)
    assert ("lodash", "4.17.4", ECOSYSTEM_NPM) in got
    assert ("express", "4.16.0", ECOSYSTEM_NPM) in got
    assert ("@types/node", "18.0.0", ECOSYSTEM_NPM) in got
    # Root project entry ("") is never emitted as a dependency.
    assert ("sample-app", "1.0.0", ECOSYSTEM_NPM) not in got
