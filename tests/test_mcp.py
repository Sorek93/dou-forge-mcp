"""SDK interoperability/auth tests. Never connect to a production host or IdP."""
import asyncio
import json
import secrets
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from starlette.testclient import TestClient

from douforge.config import Config, ForgeError
from douforge.server import Verifier, create_server


def preview(setup, monkeypatch):
    _, raw, path, _ = setup
    raw["http"] = {"auth_mode": "preview", "issuer_url": "http://127.0.0.1:9384",
                   "resource_url": "http://127.0.0.1:9384/mcp", "preview_principal": "local"}
    path.write_text(json.dumps(raw))
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN", token)
    return raw, path, token


@pytest.mark.asyncio
async def test_sdk_discovery_and_typed_results(setup):
    forge, _, path, calls = setup
    server, _ = create_server(path, forge.state.path.parent, runner=forge.runner)
    async with Client(server) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools.tools}
        assert names == {"bus_hosts", "bus_plan", "bus_exec", "bus_receipt"}
        assert "approve" not in names
        assert all(t.output_schema is not None for t in tools.tools)
        result = await client.call_tool("bus_hosts")
        assert not result.is_error
        assert result.structured_content["hosts"][0]["alias"] == "box"
        assert result.content and "box" in result.content[0].text
        plan = await client.call_tool("bus_plan", {"hosts": ["box"], "action": "hostname"})
        plan_id = plan.structured_content["plan_id"]
        denied = await client.call_tool("bus_exec", {"plan_id": plan_id, "request_id": "sdk-1", "confirm": True})
        assert denied.is_error and calls == []
        invalid = await client.call_tool("bus_exec", {"plan_id": plan_id, "request_id": "sdk-1", "confirm": 1})
        assert invalid.is_error and calls == []
        forge.approve(plan_id)
        result = await client.call_tool("bus_exec", {"plan_id": plan_id, "request_id": "sdk-1", "confirm": True})
        assert not result.is_error and result.structured_content["ok"]
        replay = await client.call_tool("bus_exec", {"plan_id": plan_id, "request_id": "sdk-1", "confirm": True})
        assert replay.structured_content["replayed"] and len(calls) == 1
        receipt = await client.call_tool("bus_receipt", {"request_id": "sdk-1"})
        assert receipt.structured_content["status"] == "completed"


def test_preview_requires_strong_token(setup, monkeypatch):
    _, path, _ = preview(setup, monkeypatch)
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN", "weak")
    with pytest.raises(ForgeError):
        Verifier(path)


def test_preview_cannot_advertise_public_endpoint(setup, monkeypatch):
    raw, _, _ = preview(setup, monkeypatch)
    raw["http"]["resource_url"] = "https://mcp.example.com/mcp"
    with pytest.raises(ForgeError):
        Config(raw)


def test_preview_verifier_and_revocation(setup, monkeypatch):
    raw, path, token = preview(setup, monkeypatch)
    verifier = Verifier(path)
    assert asyncio.run(verifier.verify_token(token)).subject == "local"
    assert asyncio.run(verifier.verify_token("wrong")) is None
    raw["principals"].pop("local")
    path.write_text(json.dumps(raw))
    assert asyncio.run(verifier.verify_token(token)) is None


def test_http_requires_auth_and_rejects_wrong_host(setup, monkeypatch):
    _, path, token = preview(setup, monkeypatch)
    server, _ = create_server(path, setup[0].state.path.parent, transport="streamable-http", runner=setup[0].runner)
    app = server.streamable_http_app(json_response=True, stateless_http=True, host="127.0.0.1")
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}
    headers = {"Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="http://127.0.0.1:9384") as client:
        assert client.post("/mcp", json=request, headers=headers).status_code == 401
        assert client.post("/mcp", json=request, headers={**headers, "Authorization": "Bearer wrong"}).status_code == 401
        authed = {**headers, "Authorization": "Bearer " + token}
        assert client.post("/mcp", json=request, headers=authed).status_code == 200
        bad = client.post("/mcp", json=request, headers={**authed, "Host": "attacker.example"})
        assert bad.status_code in {400, 403, 421}
        listing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=authed)
        assert listing.status_code == 200 and len(listing.json()["result"]["tools"]) == 4
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "bus_hosts", "arguments": {}}}, headers=authed)
        assert response.status_code == 200
        data = response.json()["result"]
        assert data["structuredContent"]["hosts"][0]["alias"] == "box"
        assert "box" in data["content"][0]["text"]
        # Authentication is through the actual HTTP middleware, not the in-memory client.
        assert not setup[3]


def jwt_setup(setup, monkeypatch):
    _, raw, path, _ = setup
    raw["http"] = {"auth_mode": "jwt", "issuer_url": "https://issuer.example.com",
                   "resource_url": "https://forge.example.com/mcp", "jwks_url": "https://issuer.example.com/jwks"}
    path.write_text(json.dumps(raw))
    verifier = Verifier(path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(verifier.jwks, "get_signing_key_from_jwt", lambda _: SimpleNamespace(key=key.public_key()))
    claims = {"iss": raw["http"]["issuer_url"], "aud": raw["http"]["resource_url"],
              "sub": "local", "scope": "forge:use", "exp": int(time.time()) + 60}
    return verifier, key, claims


def test_jwt_signature_issuer_audience_and_subject(setup, monkeypatch):
    verifier, key, claims = jwt_setup(setup, monkeypatch)
    token = jwt.encode(claims, key, algorithm="RS256")
    assert asyncio.run(verifier.verify_token(token)).subject == "local"


@pytest.mark.parametrize("field,value", [("iss", "https://wrong.example.com"), ("aud", "another-resource"),
    ("sub", "stranger"), ("scope", "unrelated"), ("exp", 1), ("scope", ["forge:use"])])
def test_jwt_rejects_claim_mismatch(setup, monkeypatch, field, value):
    verifier, key, claims = jwt_setup(setup, monkeypatch)
    claims[field] = value
    assert asyncio.run(verifier.verify_token(jwt.encode(claims, key, algorithm="RS256"))) is None


def test_jwt_rejects_bad_signature(setup, monkeypatch):
    verifier, _, claims = jwt_setup(setup, monkeypatch)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert asyncio.run(verifier.verify_token(jwt.encode(claims, other, algorithm="RS256"))) is None


def test_jwt_provider_failure_is_closed(setup, monkeypatch):
    verifier, key, claims = jwt_setup(setup, monkeypatch)
    def fail(_):
        raise OSError("provider unavailable")
    monkeypatch.setattr(verifier.jwks, "get_signing_key_from_jwt", fail)
    assert asyncio.run(verifier.verify_token(jwt.encode(claims, key, algorithm="RS256"))) is None
