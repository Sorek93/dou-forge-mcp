"""Read a preview bearer token from exactly one explicit source; never log it."""
from __future__ import annotations

import os
from pathlib import Path

from .config import ForgeError


def read_preview_token() -> str:
    value = os.environ.get("DOUFORGE_PREVIEW_TOKEN", "")
    filename = os.environ.get("DOUFORGE_PREVIEW_TOKEN_FILE", "")
    if value and filename:
        raise ForgeError("Choose a preview token or token file, not both")
    if filename:
        try:
            with Path(filename).open("rb") as stream:
                data = stream.read(4097)
            if len(data) > 4096:
                raise ValueError()
            value = data.decode("ascii").rstrip("\r\n")
        except (OSError, ValueError, UnicodeError):
            raise ForgeError("Preview token file is unreadable or invalid") from None
    if not 32 <= len(value) <= 4096 or not value.isascii() or any(c.isspace() for c in value):
        raise ForgeError("Preview token must contain 32–4096 non-whitespace ASCII characters")
    if any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ForgeError("Preview token contains unsupported characters")
    return value
