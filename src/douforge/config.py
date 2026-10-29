"""Strict configuration. No discovery of production files or implicit SSH hosts."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


class ForgeError(ValueError):
    """An expected, safe-to-return denial or validation error."""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _keys(value: object, allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) - allowed:
        raise ForgeError(f"Invalid {label} object or unknown fields")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ForgeError("Invalid name or SSH alias")
    return value


def _integer(value: object, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ForgeError(f"Expected integer in [{low}, {high}]")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ForgeError("Expected boolean")
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ForgeError("Duplicate JSON key")
        result[key] = value
    return result


def _url(value: object, *, loopback: bool = False) -> str:
    if not isinstance(value, str):
        raise ForgeError("URL must be a string")
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment or parsed.query or not parsed.hostname:
        raise ForgeError("Invalid URL")
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if loopback and not local:
        raise ForgeError("Preview auth is loopback-only")
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ForgeError("HTTPS required except on loopback")
    return value


class Config:
    """Validated immutable snapshot, reloaded before planning and execution."""

    def __init__(self, raw: dict):
        raw = json.loads(canonical(raw))
        _keys(raw, {"version", "execution_enabled", "shell_enabled", "ssh_config", "limits",
                    "hosts", "actions", "principals", "http"}, "configuration")
        if type(raw.get("version")) is not int or raw["version"] != 1:
            raise ForgeError("version must be 1")
        self.execution_enabled = _boolean(raw.get("execution_enabled", False))
        self.shell_enabled = _boolean(raw.get("shell_enabled", False))
        self.ssh_config = raw.get("ssh_config")
        if self.ssh_config is not None:
            if not isinstance(self.ssh_config, str) or not Path(self.ssh_config).is_absolute():
                raise ForgeError("ssh_config must be an explicit absolute path")
        limits = _keys(raw.get("limits", {}), {"timeout_s", "output_bytes", "hard_output_bytes",
                      "max_hosts", "plan_ttl_s", "max_records"}, "limits")
        self.timeout_s = _integer(limits.get("timeout_s", 15), 1, 60)
        self.output_bytes = _integer(limits.get("output_bytes", 32768), 256, 65536)
        self.hard_output_bytes = _integer(limits.get("hard_output_bytes", 1048576), self.output_bytes, 8388608)
        self.max_hosts = _integer(limits.get("max_hosts", 4), 1, 8)
        self.plan_ttl_s = _integer(limits.get("plan_ttl_s", 300), 10, 900)
        self.max_records = _integer(limits.get("max_records", 1000), 10, 100000)
        self.hosts = _keys(raw.get("hosts", {}), set(raw.get("hosts", {})), "hosts")
        for alias, host in self.hosts.items():
            _name(alias)
            _keys(host, {"ssh_alias", "tags"}, "host")
            _name(host.get("ssh_alias", alias))
            tags = host.get("tags", [])
            if not isinstance(tags, list) or len(tags) > 20 or any(not isinstance(t, str) or len(t) > 64 for t in tags):
                raise ForgeError("Invalid tags")
        self.actions = _keys(raw.get("actions", {}), set(raw.get("actions", {})), "actions")
        for name, action in self.actions.items():
            _name(name)
            if name == "shell":
                raise ForgeError("shell is reserved")
            _keys(action, {"command", "require_approval"}, "action")
            self.validate_command(action.get("command"))
            _boolean(action.get("require_approval", True))
        self.principals = _keys(raw.get("principals", {}), set(raw.get("principals", {})), "principals")
        for principal, rights in self.principals.items():
            if not isinstance(principal, str) or not principal or len(principal) > 256:
                raise ForgeError("Invalid principal")
            _keys(rights, {"hosts", "actions"}, "principal rights")
            for field, known in (("hosts", set(self.hosts)), ("actions", set(self.actions) | {"shell"})):
                values = rights.get(field, [])
                if not isinstance(values, list) or any(not isinstance(v, str) or v not in known for v in values):
                    raise ForgeError("Unknown host/action in principal rights")
        self.http = _keys(raw.get("http", {}), {"auth_mode", "issuer_url", "resource_url", "jwks_url",
                          "preview_principal"}, "http")
        if self.http:
            mode = self.http.get("auth_mode")
            if mode not in {"jwt", "preview"}:
                raise ForgeError("HTTP requires jwt or explicit preview auth")
            _url(self.http.get("issuer_url"), loopback=mode == "preview")
            _url(self.http.get("resource_url"), loopback=mode == "preview")
            if mode == "jwt":
                jwks = _url(self.http.get("jwks_url"))
                if urlsplit(jwks).scheme != "https" or urlsplit(self.http["issuer_url"]).scheme != "https":
                    raise ForgeError("JWT issuer and JWKS must use HTTPS")
            elif self.http.get("preview_principal") not in self.principals:
                raise ForgeError("Preview principal not configured")
        self.raw = raw
        self.fingerprint = digest(raw)

    @staticmethod
    def validate_command(command: object) -> str:
        if not isinstance(command, str) or not command.strip() or "\x00" in command or len(command.encode()) > 8192:
            raise ForgeError("Command is empty, invalid, or too large")
        return command

    def rights(self, principal: str) -> dict:
        if principal not in self.principals:
            raise ForgeError("Principal is not authorized")
        return self.principals[principal]


def load_config(path: Path) -> Config:
    try:
        data = path.read_bytes()
        if len(data) > 1048576:
            raise ForgeError("Configuration too large")
        return Config(json.loads(data, object_pairs_hook=_no_duplicates))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, KeyError) as exc:
        raise ForgeError("Configuration missing or invalid; execution denied") from exc
