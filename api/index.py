"""Vercel serverless WSGI entrypoint for Cornea-Guard."""

from __future__ import annotations

import os
import sys

_ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from app import app  # noqa: E402, F401
