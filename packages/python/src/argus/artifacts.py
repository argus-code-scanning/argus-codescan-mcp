"""Keep a scan run's temporary files in one private directory (#60).

Argus and the scanners it launches (gitleaks, semgrep, trivy, ...) write
temporary files such as raw tool reports, which can contain secrets or PII.
By default those land in the shared system temp directory and, for external
tools, are not always cleaned up. ``private_temp_dir`` points ``TMPDIR`` /
``TMP`` / ``TEMP`` and Python's :mod:`tempfile` at a fresh 0700 directory for
the duration of a run, so child processes inherit it, and removes the
directory afterwards even if the scan fails.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_TEMP_ENV_VARS = ("TMPDIR", "TMP", "TEMP")


@contextmanager
def private_temp_dir(parent: str | Path | None = None) -> Iterator[Path]:
    """Redirect temporary files for this process and its children; delete them on exit."""
    if parent is not None:
        Path(parent).mkdir(parents=True, exist_ok=True)
    # mkdtemp creates the directory with mode 0700.
    run_dir = tempfile.mkdtemp(prefix="argus-run-", dir=parent)
    saved_env = {name: os.environ.get(name) for name in _TEMP_ENV_VARS}
    saved_tempdir = tempfile.tempdir
    try:
        for name in _TEMP_ENV_VARS:
            os.environ[name] = run_dir
        tempfile.tempdir = run_dir
        yield Path(run_dir)
    finally:
        tempfile.tempdir = saved_tempdir
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(run_dir, ignore_errors=True)
