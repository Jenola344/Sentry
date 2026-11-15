"""Shared fixtures for the Sentry engine test suite.

The engine is a flat script package (`sentry_cli.py` imports `rules` directly),
so the engine directory is placed on sys.path before anything is imported.
"""

import sys
from pathlib import Path

import pytest

ENGINE_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ENGINE_DIR / "sample_nas"
for path in (ENGINE_DIR, FIXTURE_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


@pytest.fixture
def engine_dir() -> Path:
    return ENGINE_DIR


@pytest.fixture
def share(tmp_path: Path) -> Path:
    """An audited storage root."""
    root = tmp_path / "Shared"
    root.mkdir()
    return root


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    """A quarantine vault outside the audited root."""
    return tmp_path / "Private_Security_Vault"


@pytest.fixture
def write_file():
    def _write(path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def make_cli(share: Path, vault: Path):
    """Builds a SentryCLI over the temporary share/vault pair."""
    from sentry_cli import SentryCLI

    def _make(target=None, vault_path=None, **kwargs):
        return SentryCLI(
            target_path=Path(target) if target else share,
            vault_path=Path(vault_path) if vault_path else vault,
            **kwargs
        )

    return _make


@pytest.fixture
def manifest_rows():
    """Extracts manifest table rows from a quarantine-manifest.md file."""
    from sentry_cli import MANIFEST_ROW_RE

    def _rows(manifest_path: Path):
        return [
            MANIFEST_ROW_RE.match(line)
            for line in manifest_path.read_text(encoding="utf-8").splitlines()
            if MANIFEST_ROW_RE.match(line)
        ]

    return _rows
