"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Threat-intel feed caches go to a temp dir, never the developer's ~/.cache/argus."""
    monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path_factory.mktemp("argus-cache")))
    monkeypatch.delenv("ARGUS_ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("ARGUS_IOC_FILE", raising=False)


@pytest.fixture(autouse=True)
def _no_network_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep online lookups (the OSV malicious-package check) out of unit tests.

    Tests that exercise the lookup remove this with ``monkeypatch.delenv`` and mock OSV.
    """
    monkeypatch.setenv("ARGUS_NO_NETWORK", "1")
