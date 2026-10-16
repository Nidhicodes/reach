"""Where bundled data lives, in a git checkout and in an installed wheel alike.

A checkout keeps `data/` and `examples/` at the repo root; the wheel force-includes
them under `reach/_bundled/` (see pyproject.toml), so `uvx --from git+...` works.
"""

from __future__ import annotations

import pathlib

_PKG = pathlib.Path(__file__).resolve().parent
_REPO = _PKG.parent


def _pick(rel: str) -> pathlib.Path:
    repo = _REPO / rel
    return repo if repo.exists() else _PKG / "_bundled" / rel


DATA = _pick("data")
EXAMPLES = _pick("examples")
