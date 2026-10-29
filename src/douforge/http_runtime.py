"""Explicit HTTP bind policy and a minimal configuration liveness endpoint."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config, ForgeError, load_config


def validate_bind(config: Config, host: str, container_preview: bool = False) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ForgeError("Listen address must be a literal IP address") from None
    if not config.http:
        raise ForgeError("HTTP authentication is not configured")
    if not address.is_loopback and config.http["auth_mode"] == "preview" and not container_preview:
        raise ForgeError("Non-loopback preview requires explicit --container-preview and host-side isolation")
    if container_preview and (config.http["auth_mode"] != "preview" or host != "0.0.0.0"):
        raise ForgeError("--container-preview is only for preview on 0.0.0.0 behind a loopback port mapping")


def http_app(server, config_path: Path, host: str):
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    cfg = load_config(config_path)
    expected_http = cfg.http.copy()
    allowed = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    resource_host = urlsplit(cfg.http["resource_url"]).netloc
    if resource_host not in allowed:
        allowed.append(resource_host)
    app = server.streamable_http_app(json_response=True, stateless_http=True,
        max_request_body_size=65536, host=host,
        transport_security=TransportSecuritySettings(allowed_hosts=allowed, allowed_origins=[]))

    async def health(_):
        try:
            if load_config(config_path).http != expected_http:
                raise ForgeError("Authentication configuration changed")
        except ForgeError:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    # No tokens, hostnames, command results or state are exposed here.
    # This is process/config liveness, NOT an SSH, IdP or application acceptance test.
    app.routes.append(Route("/healthz", health, methods=["GET"]))
    return app
