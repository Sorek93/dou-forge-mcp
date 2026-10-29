"""Offline preflight for first-time operators; never connects or executes a command."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config import Config


def diagnose(
    cfg: Config,
    state_dir: Path,
    *,
    ssh_path: str | None = None,
    platform_name: str | None = None,
) -> dict:
    """Inspect only local configuration and file metadata; no credentials are read.

    No process launch, SSH connection, OAuth request, configuration creation or
    state database mutation occurs. A clean result is NOT deployment acceptance.
    """
    checks: list[dict] = []

    def add(name: str, status: str, advice: str = "") -> None:
        checks.append({"name": name, "status": status, "advice": advice})

    platform_value = os.name if platform_name is None else platform_name
    add("controller_os", "pass" if platform_value == "posix" else "fail",
        "" if platform_value == "posix" else "Controller requires Linux or macOS")

    path = shutil.which("ssh") if ssh_path is None else ssh_path
    add("ssh_client_found", "pass" if path else "fail",
        "" if path else "Install an OpenSSH client on the controller")

    if cfg.ssh_config is None:
        add("explicit_ssh_config", "warn",
            "No separate SSH config set; confirm aliases and host keys before enabling execution")
    else:
        target = Path(cfg.ssh_config)
        ok = target.is_file() and not target.is_symlink()
        add("explicit_ssh_config", "pass" if ok else "fail",
            "" if ok else "The configured SSH config file is absent or a symlink")

    state = state_dir.absolute()
    if state.is_symlink():
        add("state_permissions", "fail", "Use a private, non-symlink state directory")
    elif not state.exists():
        add("state_permissions", "warn",
            "State is not initialized; first serve will create a private directory")
    elif not state.is_dir():
        add("state_permissions", "fail", "State path is not a directory")
    else:
        stat = state.stat()
        ok = not stat.st_mode & 0o077 and (not hasattr(os, "getuid") or stat.st_uid == os.getuid())
        db = state / "state.sqlite3"
        if db.is_symlink():
            ok = False
        elif db.exists():
            info = db.stat()
            ok = ok and db.is_file() and not info.st_mode & 0o077
            if hasattr(os, "getuid"):
                ok = ok and info.st_uid == os.getuid()
        add("state_permissions", "pass" if ok else "fail",
            "" if ok else "State must be owned by the process user (dir 0700, DB 0600)")

    add("configured_hosts", "pass" if cfg.hosts else "warn",
        "" if cfg.hosts else "Add only reviewed SSH aliases; none are imported automatically")
    add("execution_switch", "pass" if cfg.execution_enabled else "warn",
        "" if cfg.execution_enabled else "Execution is disabled by default; enable only after SSH review")
    add("shell_policy", "warn" if cfg.shell_enabled else "pass",
        "Free shell is powerful; keep it off for untrusted callers" if cfg.shell_enabled else "")
    add("authorized_principals", "pass" if cfg.principals else "warn",
        "" if cfg.principals else "No callers have been authorized")

    if not cfg.http:
        add("remote_auth", "warn", "Stdio-only; remote clients need external OAuth and JWT configuration")
    elif cfg.http["auth_mode"] == "preview":
        add("remote_auth", "warn", "Preview is local-only; do not tunnel or publish its bearer token")
    else:
        add("remote_auth", "warn",
            "JWT resource-server settings exist; independently validate the IdP and perform a real OAuth login")

    return {
        "status": "blocked" if any(c["status"] == "fail" for c in checks) else "offline_preflight_only",
        "checks": checks,
        "verified": {
            "ssh_connection": False, "remote_execution": False,
            "oauth_login": False, "chatgpt_connector": False,
        },
        "warning": "This command does not test remote hosts or authorize public deployment.",
    }
