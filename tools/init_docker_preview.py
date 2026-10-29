#!/usr/bin/env python3
"""Create a NEW isolated local preview config; never inspect/import existing SSH credentials."""
from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path


def initialize(root: Path, port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("Port must be 1–65535")
    # Refuse all existing destinations, including symlinks: no accidental rotation/overwrite.
    root.mkdir(mode=0o700, exist_ok=False)
    config = {"version": 1, "execution_enabled": False, "shell_enabled": False,
        "hosts": {}, "actions": {"hostname": {"command": "hostname", "require_approval": True}},
        "principals": {"local": {"hosts": [], "actions": ["hostname"]}},
        "http": {"auth_mode": "preview", "issuer_url": f"http://127.0.0.1:{port}",
                 "resource_url": f"http://127.0.0.1:{port}/mcp", "preview_principal": "local"}}
    (root / "ssh").mkdir(mode=0o755)
    contents = {"config.json": json.dumps(config, indent=2) + "\n",
                "preview.token": secrets.token_urlsafe(48) + "\n",
                "ssh/config": "# Deliberately empty. Add dedicated, least-privilege SSH aliases yourself.\n",
                "ssh/known_hosts": ""}
    for name, content in contents.items():
        path = root / name
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
        # The 0700 parent protects host traversal; read-only Compose file mounts need UID 10001 access.
        # Compose file-backed secrets may preserve host permissions, not remap uid/mode.
        path.chmod(0o444)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("runtime"))
    parser.add_argument("--port", type=int, default=9384)
    args = parser.parse_args()
    try:
        initialize(args.directory, args.port)
    except (OSError, ValueError):
        print("Not initialized: check the port and choose a NEW directory. Existing files are never replaced.")
        return 2
    print("Local preview initialized. Token saved to the private runtime directory; no credentials printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
