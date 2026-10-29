# Dou Forge MCP — community core

**Your AI. Your machines. One control plane.**

Apache-2.0 community candidate `0.1.0a4`. This directory is a release candidate, **not yet a public release**.
The Apache-2.0 license is included at the repository root. Complete security review, independent installation and real ChatGPT OAuth onboarding remain release gates.
Do not publish the parent private repository or its history; the license applies only to this independently reviewed community tree.

Dou Forge connects an MCP conversation to explicitly authorized user-owned machines through OpenSSH.
This initial core implements `bus_hosts`, `bus_plan`, `bus_exec`, and `bus_receipt`.
It is deliberately independent of private knowledge bases, source repositories, collaboration services and accelerator fleets.
Those are **not included or claimed to be implemented in this edition**.

## Install and validate

Controller: Linux/macOS, Python 3.11+, OpenSSH. Targets use administrator-managed SSH aliases.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
douforge --config examples/config.json check
python -m pytest -q
```

The sample has no hosts, execution disabled, and free shell disabled. It never discovers your
existing SSH hosts or private service configurations. Never paste a production token into source.

## Offline first-run diagnostics

Run before configuring any real machine:

    douforge --config examples/config.json --state "$HOME/.local/state/douforge-demo" doctor

Doctor makes no network requests, executes no commands, reads no credentials,
and does not create a state database. It checks local prerequisites and
reports missing SSH config, insecure state permissions and disabled actions.
A status of offline_preflight_only DOES NOT prove an SSH connection,
OAuth login or ChatGPT acceptance. Continue with oauth-check, an operator
approved test action, and a real client only in an isolated environment.

## Start with stdio

```sh
douforge --config examples/config.json --state "$HOME/.local/state/douforge-demo" serve
```

An MCP-capable local client may launch this command. Stdio uses the `local` principal and inherits
the launcher's OS privileges. It is **not authenticated HTTP** and does not make ChatGPT able to
reach a local pipe.

## Add one machine deliberately

Copy `examples/config.json` to an ignored `config.local.json`. Add an existing SSH alias:

```json
"hosts": {"demo": {"ssh_alias": "my-test-host", "tags": ["lab"]}},
"principals": {"local": {"hosts": ["demo"], "actions": ["hostname"]}}
```

Verify that alias and its host key as the operator. Set `execution_enabled: true` only after reviewing
access. The default `hostname` action requires local operator approval:

1. The MCP client calls `bus_plan(hosts=["demo"], action="hostname")`.
2. The operator reviews the exact command and hosts using the local command below.
3. The MCP client calls `bus_exec(plan_id=..., request_id="a-stable-unique-id", confirm=true)`.
4. Repeating the same request returns its receipt rather than running the command twice.

```sh
douforge --config config.local.json --state "$HOME/.local/state/douforge-demo" approve PLAN_ID
```

Approval is **not exposed as an MCP tool**. `confirm=true` cannot replace it. An operator can mark a
specific named action `require_approval: false`; that is a standing authorization, not a claim the
command is intrinsically safe. Free shell is separately disabled and always requires approval.

## HTTP and authentication

Loopback preview (no OAuth login service is provided in this mode):

```sh
export DOUFORGE_PREVIEW_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
douforge --config examples/config.json --state "$HOME/.local/state/douforge-preview" \
  serve --transport streamable-http --port 9384
```

The native server binds **127.0.0.1 by default**, requires the bearer token, and refuses a public resource URL in
preview mode. Never expose preview with a tunnel or reverse proxy. This mode tests HTTP middleware;
it is not the ChatGPT signup experience.

For remote OAuth clients, configure `http.auth_mode: "jwt"`, your HTTPS `issuer_url`, HTTPS
`jwks_url` and intended `resource_url`. Tokens must be signed with RS256/ES256, match issuer and
audience, include expiry, subject and `forge:use` scope. Configure that exact subject in `principals`.
The official MCP SDK advertises protected-resource metadata. Bring an OAuth 2.1 authorization
server with an appropriate client registration/consent flow and a TLS reverse proxy. This package
does not create an identity provider, issue tokens, or silently trust Tailscale/private IPs.

**ChatGPT OAuth end-to-end onboarding of this new edition remains unverified.** The functioning
private deployment is a separate implementation and must not be used as proof for this edition.

## Safety and limitations

Read [SECURITY.md](SECURITY.md). This is an automation control plane, **not a sandbox**. SSH executes
with the selected remote account's privileges. Protect the controller and use least-privilege users.
An arbitrary-shell action on the controller account can defeat same-account approval separation;
do not grant it to untrusted clients. Admin configuration and OS isolation remain trust boundaries.

Plans are short-lived, bound to the configuration and caller, and single-use. SQLite receipts persist
across restart. A crash after claim can leave an uncertain outcome; the server refuses to retry it.
This is not exactly-once execution of distributed side effects. Inspect the remote host manually.

Output is bounded in memory, with an additional stop threshold. There is no unlimited full-output log.
Timeouts terminate the local SSH process group; remote descendant termination is **not guaranteed**.
A multi-host operation may partially complete; it is not an atomic distributed transaction.

## Development and provenance

Use `python -m pytest -q`, `ruff check src tests`, and `python -m build` in this directory.
Core behavior is new code informed by the private bus workflow; it is not a bulk export of private
source. No private backend modules, deployment files, repository history, secrets, corpus or host list
is included. Dependencies are installed from upstream, not vendored. See [PROVENANCE.md](PROVENANCE.md).

## Docker packaging

See [Docker / Compose guide](DOCKER.zh-CN.md). Run `python3 tools/init_docker_preview.py`, then
`docker compose up --build --detach --wait` in this community directory. The preview publishes
only to host loopback, uses a generated file-backed token and a non-root, read-only container.
The explicit `--container-preview` flag permits container-internal all-interface binding; it
cannot enforce host-side isolation for you. Never expose preview through a public tunnel.
For externally authenticated use, configure an HTTPS JWT issuer/resource and use the
`compose.jwt.yaml` override; a complete OAuth login server is still operator-provided.
No registry images are published by these files. Dockerfile architecture portability is not
proof of acceptance on every architecture. See the recorded Docker smoke test results.

## OAuth preflight

Run `douforge --config CONFIG oauth-check --registration provided` against administrator-reviewed configuration. This performs bounded, authenticated-TLS metadata reads only; it does not log in, register a client, or prove ChatGPT interoperability. See `OAUTH.zh-CN.md` for the separate onboarding checklist.

