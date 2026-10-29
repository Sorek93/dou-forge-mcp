"""Container entrypoints and security defaults; real Docker smoke tests are separate."""
import asyncio
import importlib.util
import json
import secrets
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from douforge.config import Config, ForgeError
from douforge.http_runtime import http_app, validate_bind
from douforge.preview_token import read_preview_token
from douforge.server import Verifier, create_server

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_token_env(monkeypatch):
    monkeypatch.delenv("DOUFORGE_PREVIEW_TOKEN", raising=False)
    monkeypatch.delenv("DOUFORGE_PREVIEW_TOKEN_FILE", raising=False)


def preview_config():
    return Config(json.loads((ROOT / "examples/config.json").read_text()))


def test_preview_loopback_is_default():
    validate_bind(preview_config(), "127.0.0.1")
    validate_bind(preview_config(), "::1")


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "::"])
def test_preview_nonloopback_needs_explicit_ack(host):
    with pytest.raises(ForgeError):
        validate_bind(preview_config(), host)


def test_container_preview_explicit():
    validate_bind(preview_config(), "0.0.0.0", True)
    with pytest.raises(ForgeError):
        validate_bind(preview_config(), "127.0.0.1", True)


@pytest.mark.parametrize("host", ["localhost", "bad", "127.0.0.1:9384"])
def test_bind_requires_ip_literal(host):
    with pytest.raises(ForgeError):
        validate_bind(preview_config(), host)


def test_jwt_all_interface_bind():
    raw = preview_config().raw
    raw["http"] = {"auth_mode": "jwt", "issuer_url": "https://auth.example.com",
                   "jwks_url": "https://auth.example.com/jwks", "resource_url": "https://mcp.example.com/mcp"}
    cfg = Config(raw)
    validate_bind(cfg, "0.0.0.0")
    with pytest.raises(ForgeError):
        validate_bind(cfg, "0.0.0.0", True)


def test_token_file_and_env(monkeypatch, tmp_path):
    token = secrets.token_urlsafe(48)
    path = tmp_path / "token"
    path.write_text(token + "\n")
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN_FILE", str(path))
    assert read_preview_token() == token
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN", token)
    with pytest.raises(ForgeError):
        read_preview_token()


@pytest.mark.parametrize("value", ["x", "x"*4097, "x"*32+" y", "x"*32+"\x00", "密码"*32])
def test_invalid_tokens_fail_closed(monkeypatch, value):
    # Environment variables cannot contain NUL, so test file contents instead.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = Path(td)/"token"
        path.write_text(value)
        monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN_FILE", str(path))
        with pytest.raises(ForgeError):
            read_preview_token()


def test_missing_token_file(monkeypatch, tmp_path):
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN_FILE", str(tmp_path/"missing"))
    with pytest.raises(ForgeError):
        read_preview_token()


def test_health_and_file_auth(tmp_path, monkeypatch):
    path = tmp_path/"config.json"
    path.write_text(json.dumps(preview_config().raw))
    token = secrets.token_urlsafe(48)
    key = tmp_path/"token"
    key.write_text(token)
    monkeypatch.setenv("DOUFORGE_PREVIEW_TOKEN_FILE", str(key))
    assert asyncio.run(Verifier(path).verify_token(token)).subject == "local"
    server, _ = create_server(path, tmp_path/"state", transport="streamable-http")
    with TestClient(http_app(server, path, "0.0.0.0"), base_url="http://127.0.0.1:9384") as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.post("/mcp", json={}).status_code == 401
        path.write_text("invalid")
        response = client.get("/healthz")
        assert response.status_code == 503 and token not in response.text


def test_initializer_does_not_import_or_overwrite(tmp_path):
    spec = importlib.util.spec_from_file_location("init_preview", ROOT/"tools/init_docker_preview.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path/"new"
    module.initialize(root, 9384)
    before = (root/"preview.token").read_bytes()
    cfg = json.loads((root/"config.json").read_text())
    assert cfg["hosts"] == {} and not cfg["execution_enabled"]
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root/"preview.token").stat().st_mode & 0o777 == 0o444
    with pytest.raises(FileExistsError):
        module.initialize(root, 9384)
    assert (root/"preview.token").read_bytes() == before


def test_compose_safe_defaults_and_build_allowlist():
    text = (ROOT/"compose.yaml").read_text()
    for value in ['127.0.0.1:${DOUFORGE_PORT:-9384}:9384', 'read_only: true',
                  'cap_drop: [ALL]', 'no-new-privileges:true', 'create_host_path: false']:
        assert value in text
    assert 'docker.sock' not in text and 'privileged:' not in text and 'network_mode: host' not in text
    assert (ROOT/".dockerignore").read_text().splitlines()[1] == '**'
    assert 'USER 10001:10001' in (ROOT/"Dockerfile").read_text()
