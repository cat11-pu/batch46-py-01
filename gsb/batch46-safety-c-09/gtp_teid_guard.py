"""Compatibility path for the task layout.

The executable implementation lives at the repository root so it can be
imported directly by ``import gtp_teid_guard``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


_ROOT_MODULE = Path(__file__).resolve().parents[2] / "gtp_teid_guard.py"
_SPEC = importlib.util.spec_from_file_location(
    "_gsb_gtp_teid_guard_impl", _ROOT_MODULE
)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"cannot load {_ROOT_MODULE}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

GtpError = _MODULE.GtpError
GtpGuard = _MODULE.GtpGuard

__all__ = ["GtpError", "GtpGuard"]
