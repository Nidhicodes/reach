"""Reach: attack paths AI agents open up, and how to close them. Built on FalkorDB."""

import os as _os
from pathlib import Path as _Path


def _load_env(path: _Path = _Path(__file__).resolve().parent.parent / ".env") -> None:
    """Minimal .env loader (no dependency). Real environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            _os.environ.setdefault(k.strip(), v.strip())


if not _os.environ.get("REACH_NO_DOTENV"):
    _load_env()
