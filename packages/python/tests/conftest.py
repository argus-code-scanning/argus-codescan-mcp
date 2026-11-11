"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_network_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep online lookups (the OSV malicious-package check) out of unit tests.

    Tests that exercise the lookup remove this with ``monkeypatch.delenv`` and mock OSV.
    """
    monkeypatch.setenv("ARGUS_NO_NETWORK", "1")
