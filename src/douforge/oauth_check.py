"""Read-only operator preflight; metadata readiness is NOT a completed OAuth login."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config, ForgeError

MAX_DOCUMENT = 131072


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ForgeError("Discovery redirects are not followed; configure canonical endpoints")


def _https(url: object) -> str:
    if not isinstance(url, str):
        raise ForgeError("Discovery URL must be HTTPS")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ForgeError("Discovery URL must be canonical HTTPS without credentials")
    return url


def get_json(url: str, *, ca_file: Path | None = None) -> dict:
    """No tokens, cookies, client secrets, redirects or environment proxy credentials."""
    _https(url)
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(MAX_DOCUMENT + 1)
        if len(raw) > MAX_DOCUMENT:
            raise ForgeError("Discovery document exceeds size limit")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ForgeError("Discovery document must be an object")
        return data
    except (OSError, ValueError, urllib.error.URLError):
        # Do not print provider bodies, URL credentials or third-party exception details.
        raise ForgeError("Discovery request failed or returned invalid JSON") from None


def discovery_urls(issuer: str) -> tuple[str, ...]:
    """RFC 8414 path insertion plus OIDC discovery; issuer comparison remains exact."""
    p = urlsplit(_https(issuer))
    origin = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    return (origin + "/.well-known/oauth-authorization-server" + path,
            issuer.rstrip("/") + "/.well-known/openid-configuration")


def check_oauth(cfg: Config, *, registration: str = "provided", fetch=get_json) -> dict:
    """Fetch only configured resource/issuer/JWKS origins, never token/login endpoints.

    Run this CLI only with administrator-reviewed configuration, not a model supplied
    URL. Network requests can reach that configured network, including internal IdPs.
    """
    if registration not in {"provided", "cimd", "dcr"}:
        raise ForgeError("Unknown client registration mode")
    checks: list[dict] = []
    warnings: list[dict] = []

    def record(name: str, ok: bool, remedy: str):
        checks.append({"check": name, "ok": bool(ok), "remedy": "" if ok else remedy})

    if cfg.http.get("auth_mode") != "jwt":
        record("jwt_configuration", False, "Preview is not OAuth; configure a real HTTPS issuer and JWKS")
        return _report(checks, registration, warnings)
    try:
        resource = _https(cfg.http["resource_url"])
        issuer = _https(cfg.http["issuer_url"])
        jwks_url = _https(cfg.http["jwks_url"])
    except ForgeError:
        record("https_endpoints", False, "Resource, issuer and JWKS must all use HTTPS for remote onboarding")
        return _report(checks, registration, warnings)
    record("https_endpoints", True, "")

    def first_document(urls):
        for url in dict.fromkeys(urls):
            try:
                document = fetch(url)
                if not isinstance(document, dict):
                    raise ForgeError("Discovery object required")
                return document
            except ForgeError:
                continue
        return None

    p = urlsplit(resource)
    origin = f"{p.scheme}://{p.netloc}"
    prm = first_document([origin + "/.well-known/oauth-protected-resource" + p.path.rstrip("/"),
                          origin + "/.well-known/oauth-protected-resource"])
    record("protected_resource_discovery", prm is not None,
           "Publish unauthenticated protected resource metadata; do not protect discovery with Bearer auth")
    if prm is not None:
        record("resource_exact_match", prm.get("resource") == resource,
               "Advertise exactly the configured resource URL, including path and trailing slash")
        record("authorization_server_match", isinstance(prm.get("authorization_servers"), list)
               and issuer in prm["authorization_servers"], "Advertise the configured issuer")
        # RFC 9728 scopes_supported is OPTIONAL. MCP clients prioritize a
        # challenge's authoritative scope, so omission/non-exhaustive lists must
        # not be mislabeled a protocol failure. The actual bearer token is
        # still required to contain forge:use by server.Verifier.
        if "scopes_supported" in prm:
            scopes = prm["scopes_supported"]
            valid = isinstance(scopes, list) and bool(scopes) and all(isinstance(s, str) and s for s in scopes)
            record("scopes_supported_shape", valid, "If present, scopes_supported must be an array of strings")
            if valid and "forge:use" not in scopes:
                warnings.append({"check": "scope_advertised", "message":
                                 "forge:use not in optional scopes_supported; verify the actual 401 challenge"})
        else:
            warnings.append({"check": "scope_advertised", "message":
                             "Optional scopes_supported omitted; verify the 401 WWW-Authenticate scope"})
    metadata = first_document(discovery_urls(issuer))
    record("issuer_discovery", metadata is not None, "Publish RFC 8414 or OIDC discovery at the configured issuer")
    if metadata is not None:
        record("issuer_exact_match", metadata.get("issuer") == issuer,
               "Issuer in discovery and JWT iss must match the configured issuer exactly")
        record("pkce_s256", isinstance(metadata.get("code_challenge_methods_supported"), list)
               and "S256" in metadata["code_challenge_methods_supported"], "Publish and enforce PKCE S256")
        record("authorization_code", isinstance(metadata.get("response_types_supported"), list)
               and "code" in metadata["response_types_supported"], "Enable authorization-code responses")
        for field in ("authorization_endpoint", "token_endpoint"):
            try:
                _https(metadata.get(field))
                ok = True
            except (ForgeError, ValueError):
                ok = False
            record(field, ok, "Advertise a canonical HTTPS endpoint")
        record("jwks_url_match", metadata.get("jwks_uri") == jwks_url,
               "Configure the same JWKS URL as the issuer advertises")
        if registration == "cimd":
            record("cimd", metadata.get("client_id_metadata_document_supported") is True,
                   "Enable Client ID Metadata Documents or choose a pre-registered client")
        elif registration == "dcr":
            try:
                _https(metadata.get("registration_endpoint"))
                ok = True
            except (ForgeError, ValueError):
                ok = False
            record("dcr_endpoint", ok, "Advertise registration endpoint or choose a pre-registered client")
    keys = first_document([jwks_url])
    usable = False
    if keys and isinstance(keys.get("keys"), list):
        for key in keys["keys"]:
            if not isinstance(key, dict) or key.get("use", "sig") != "sig":
                continue
            rsa = key.get("kty") == "RSA" and key.get("n") and key.get("e") and key.get("alg", "RS256") == "RS256"
            ec = key.get("kty") == "EC" and key.get("crv") == "P-256" and key.get("x") and key.get("y") and key.get("alg", "ES256") == "ES256"
            usable = usable or bool(rsa or ec)
    record("supported_public_jwk_advertised", usable, "Publish an RSA/RS256 or P-256/ES256 signature key")
    return _report(checks, registration, warnings)


def _report(checks: list[dict], registration: str, warnings: list[dict]) -> dict:
    return {"status": "metadata_ready" if all(x["ok"] for x in checks) else "blocked",
            "registration_mode": registration, "checks": checks, "warnings": warnings,
            "login_verified": False, "chatgpt_verified": False,
            "remaining": ["Register exact callback and client authentication method",
                          "Complete code + PKCE S256 with resource at authorize and token endpoints",
                          "Verify actual JWT audience/scope/subject and operator permissions",
                          "Complete ChatGPT connection and a read-only tool invocation"]}
