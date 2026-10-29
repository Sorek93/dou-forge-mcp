"""Regression for expected denials; no real hosts, tokens or external IdP calls."""
import json
import logging
import re

import pytest
from mcp import Client
from starlette.testclient import TestClient

from douforge.server import create_server
from douforge.http_runtime import http_app


@pytest.mark.asyncio
@pytest.mark.parametrize('tool,args,message', [
    ('bus_plan', {'hosts': ['other'], 'action': 'hostname'}, 'Host not authorized'),
    ('bus_plan', {'hosts': ['box'], 'action': 'unknown'}, 'Action not authorized'),
    ('bus_plan', {'hosts': ['box'], 'action': 'hostname', 'command': 'echo not-allowed'}, 'cannot override'),
    ('bus_plan', {'hosts': ['box'], 'action': 'shell', 'command': 'hostname'}, 'Free shell is disabled'),
    ('bus_exec', {'plan_id': 'missing', 'request_id': 'bad id', 'confirm': True}, 'Invalid request_id'),
    ('bus_exec', {'plan_id': 'missing', 'request_id': 'test', 'confirm': True}, 'Plan not found'),
    ('bus_receipt', {'request_id': 'missing'}, 'Receipt not found'),
])
async def test_expected_denial_is_actionable_not_a_crash(setup, caplog, tool, args, message):
    forge, _, path, calls = setup
    server, _ = create_server(path, forge.state.path.parent, runner=forge.runner)
    async with Client(server) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error and message in result.content[0].text
    assert not calls
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.asyncio
async def test_approval_denial_preserves_next_step(setup, caplog):
    forge, _, path, calls = setup
    server, _ = create_server(path, forge.state.path.parent, runner=forge.runner)
    async with Client(server) as client:
        plan = await client.call_tool('bus_plan', {'hosts': ['box'], 'action': 'hostname'})
        result = await client.call_tool('bus_exec', {'plan_id': plan.structured_content['plan_id'],
            'request_id': 'needs-approval', 'confirm': True})
    assert result.is_error and 'Operator approval required' in result.content[0].text
    assert not calls
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.asyncio
async def test_unexpected_exception_is_not_exposed_to_client(setup):
    forge, _, path, _ = setup
    server, actual = create_server(path, forge.state.path.parent, runner=forge.runner)
    def fail(_):
        raise RuntimeError('synthetic-private-debug-value')
    actual.hosts = fail
    async with Client(server) as client:
        result = await client.call_tool('bus_hosts')
    assert result.is_error
    assert 'synthetic-private-debug-value' not in result.content[0].text


def test_jwt_resource_metadata_is_discoverable_without_a_token(setup):
    forge, raw, path, calls = setup
    # Use an exact path-form issuer to avoid guessing a provider's canonical identity.
    raw['http'] = {'auth_mode': 'jwt', 'issuer_url': 'https://identity.example.com/realms/forge',
        'resource_url': 'https://forge.example.com/mcp',
        'jwks_url': 'https://identity.example.com/realms/forge/keys'}
    path.write_text(json.dumps(raw))
    server, _ = create_server(path, forge.state.path.parent, transport='streamable-http', runner=forge.runner)
    app = http_app(server, path, '127.0.0.1')
    with TestClient(app, base_url='https://forge.example.com') as client:
        response = client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
                               headers={'Accept': 'application/json, text/event-stream'})
        assert response.status_code == 401
        match = re.search(r'resource_metadata="([^"]+)"', response.headers['www-authenticate'])
        assert match, '401 must advertise resource discovery'
        metadata = client.get(match.group(1))
        assert metadata.status_code == 200
        data = metadata.json()
        assert data['resource'] == raw['http']['resource_url']
        assert data['authorization_servers'] == [raw['http']['issuer_url']]
        assert 'forge:use' in data['scopes_supported']
        # A JWT verifier/resource server must not masquerade as a login/token issuer.
        assert client.get('/authorize').status_code == 404
        assert client.post('/token').status_code == 404
    assert not calls
