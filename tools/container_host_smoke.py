#!/usr/bin/env python3
"""Opt-in Linux integration: nonroot Docker MCP -> isolated forced-command SSH -> real host.

Requires root, Docker and existing OpenSSH server binary. Does NOT edit system sshd,
authorized_keys, firewall or production services. A fresh test-only daemon listens on
Docker's private bridge gateway; its only key can run the fixed read-only snapshot.
Temporary private keys are removed and the container/daemon stopped in finally.
Run only on an administrator-approved test host. This is NOT a public SSH deployment.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(argv, **kwargs):
    return subprocess.run(
        argv, check=True, text=True, capture_output=True, timeout=30, **kwargs
    ).stdout.strip()


def free_port(address):
    with socket.socket() as sock:
        sock.bind((address, 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--allow-isolated-host-sshd", action="store_true")
    args = parser.parse_args()
    if not args.allow_isolated_host_sshd or os.geteuid() != 0 or platform.system() != "Linux":
        parser.error("Explicit opt-in, Linux, and administrator privileges are required")
    if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", args.image):
        parser.error("Invalid image reference")
    work = args.work_dir.absolute()
    if work.exists() or not re.fullmatch(r"[A-Za-z0-9_./-]+", str(work)):
        parser.error("Use a new, simple absolute path in an isolated scratch area")
    os.umask(0o077)
    work.mkdir(parents=True, mode=0o700)
    uid = 10001
    sshd = shutil.which("sshd")
    if not sshd:
        raise RuntimeError("OpenSSH server binary must already be installed")
    image = json.loads(run(["docker", "image", "inspect", args.image]))[0]
    if image["Config"].get("User") != "10001:10001":
        raise RuntimeError("Test expects the nonroot Dou Forge runtime image")
    prior = set(run(["docker", "ps", "--format", "{{.ID}}"]).splitlines())
    network = json.loads(run(["docker", "network", "inspect", "bridge"]))[0]
    gateway = network["IPAM"]["Config"][0]["Gateway"]
    port = free_port(gateway)
    http_port = free_port("127.0.0.1")
    name = "douforge-test-host-" + secrets.token_hex(5)
    daemon = None
    container_created = False
    generated_keys: list[Path] = []
    count_file = work / "snapshot-invocations"
    report = {
        "schema_version": 1,
        "architecture": platform.machine(),
        "image_id": image["Id"],
        "scope": "real Docker bridge -> isolated host sshd -> real host read-only snapshot",
        "target_is_separate_machine": False,
        "runner_mocked": False,
        "production_authorized_keys_modified": False,
        "production_sshd_modified": False,
        "approval": "harness uses operator CLI for this explicitly authorized read-only integration",
        "checks": {},
        "passed": False,
    }
    ssh_log = (work / "sshd.log").open("w")
    try:
        client = work / "client"
        client.mkdir(mode=0o700)
        state = work / "state"
        state.mkdir(mode=0o700)
        os.chown(client, uid, uid)
        os.chown(state, uid, uid)
        for path in (work / "host_key", client / "identity"):
            generated_keys.append(path)
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)])
        for p in client.iterdir():
            os.chown(p, uid, uid)
        host_pub = (work / "host_key.pub").read_text().split()
        (client / "known_hosts").write_text(f"host-acceptance {host_pub[0]} {host_pub[1]}\n")
        (client / "config").write_text(
            f"Host host-acceptance\n  HostName {gateway}\n  HostKeyAlias host-acceptance\n"
            f"  Port {port}\n  User root\n  IdentityFile /home/douforge/.ssh/identity\n"
            "  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n"
            "  UserKnownHostsFile /home/douforge/.ssh/known_hosts\n"
        )
        for p in client.iterdir():
            os.chown(p, uid, uid)
            p.chmod(0o600)
        # No interpolation from SSH_ORIGINAL_COMMAND into a shell or executable argv.
        snapshot = work / "fixed_snapshot.py"
        snapshot.write_text(
            "import json,os,subprocess,uuid\nfrom pathlib import Path\n"
            'if os.environ.get("SSH_ORIGINAL_COMMAND") != "service_snapshot": raise SystemExit(126)\n'
            f'with Path({str(count_file)!r}).open("a") as out: out.write("snapshot\\n")\n'
            'host=subprocess.check_output(["hostname"],text=True).strip()\n'
            'services=subprocess.check_output(["docker","ps","--format","{{.Names}}|{{.Status}}"],text=True)\n'
            'print(json.dumps({"hostname":host,"nonce":uuid.uuid4().hex,"services":services.splitlines()}))\n'
        )
        authorized = work / "authorized_keys"
        authorized.write_text(
            f'restrict,command="/usr/bin/python3 {snapshot}" ' + (client / "identity.pub").read_text()
        )
        ssh_config = work / "sshd_config"
        ssh_config.write_text(
            f"Port {port}\nListenAddress {gateway}\nHostKey {work / 'host_key'}\n"
            f"PidFile {work / 'sshd.pid'}\nAuthorizedKeysFile {authorized}\n"
            "StrictModes yes\nAllowUsers root\nPermitRootLogin forced-commands-only\n"
            "PubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\nUsePAM no\nPermitEmptyPasswords no\n"
            "DisableForwarding yes\nPermitTTY no\nPermitUserRC no\nPermitUserEnvironment no\n"
            "MaxAuthTries 2\nMaxSessions 1\nLogLevel ERROR\n"
            f"ForceCommand /usr/bin/python3 {snapshot}\n"
        )
        run([sshd, "-t", "-f", str(ssh_config)])
        daemon = subprocess.Popen([sshd, "-D", "-e", "-f", str(ssh_config)], stdout=ssh_log, stderr=ssh_log)
        for _ in range(40):
            if daemon.poll() is not None:
                raise RuntimeError("Isolated SSH daemon exited; inspect private test log")
            try:
                with socket.create_connection((gateway, port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Isolated SSH daemon did not become ready")
        config = {
            "version": 1,
            "execution_enabled": True,
            "shell_enabled": False,
            "ssh_config": "/home/douforge/.ssh/config",
            "limits": {"timeout_s": 15, "output_bytes": 8192, "hard_output_bytes": 65536},
            "hosts": {"test-host": {"ssh_alias": "host-acceptance"}},
            "actions": {"service_snapshot": {"command": "service_snapshot", "require_approval": True}},
            "principals": {"local": {"hosts": ["test-host"], "actions": ["service_snapshot"]}},
            "http": {
                "auth_mode": "preview",
                "issuer_url": f"http://127.0.0.1:{http_port}",
                "resource_url": f"http://127.0.0.1:{http_port}/mcp",
                "preview_principal": "local",
            },
        }
        cp = work / "config.json"
        cp.write_text(json.dumps(config))
        cp.chmod(0o444)
        token = secrets.token_urlsafe(32)
        token_file = work / "preview.token"
        token_file.write_text(token)
        token_file.chmod(0o400)
        os.chown(token_file, uid, uid)
        command = [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            "bridge",
            "--init",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "96",
            "--log-opt",
            "max-size=2m",
            "--log-opt",
            "max-file=1",
            "--tmpfs",
            "/tmp:size=16777216,noexec,nosuid,nodev",
            "--publish",
            f"127.0.0.1:{http_port}:9384",
            "--mount",
            f"type=bind,src={cp},dst=/config/config.json,readonly",
            "--mount",
            f"type=bind,src={client},dst=/home/douforge/.ssh,readonly",
            "--mount",
            f"type=bind,src={state},dst=/data",
            "--mount",
            f"type=bind,src={token_file},dst=/run/secrets/preview_token,readonly",
            "--env",
            "DOUFORGE_PREVIEW_TOKEN_FILE=/run/secrets/preview_token",  # pragma: allowlist secret (env name only)
            image["Id"],
            "--config",
            "/config/config.json",
            "--state",
            "/data",
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "9384",
            "--container-preview",
        ]
        # Set before run: if run fails after creation, finally still removes only this unique name.
        container_created = True
        run(command)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(path, payload=None, auth=True):
            headers = {"Accept": "application/json, text/event-stream"}
            if auth:
                headers["Authorization"] = "Bearer " + token
            if payload is not None:
                headers["Content-Type"] = "application/json"
            q = urllib.request.Request(
                f"http://127.0.0.1:{http_port}" + path,
                data=json.dumps(payload).encode() if payload is not None else None,
                headers=headers,
            )
            try:
                response = opener.open(q, timeout=20)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                data = response.read(65536)
                return response.code, json.loads(data)

        def ready():
            for _ in range(80):
                try:
                    if request("/healthz", auth=False)[0] == 200:
                        return
                except (OSError, ValueError):
                    pass
                time.sleep(0.2)
            raise RuntimeError("Container HTTP did not become ready")

        def tool(name, arguments):
            code, data = request(
                "/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )
            if code != 200 or "result" not in data:
                raise RuntimeError("MCP request failed")
            return data["result"]

        ready()
        assert request("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, auth=False)[0] == 401
        report["checks"]["unauthenticated_rejected"] = True
        plan = tool("bus_plan", {"hosts": ["test-host"], "action": "service_snapshot"})["structuredContent"]
        req = {"plan_id": plan["plan_id"], "request_id": "container-host-acceptance", "confirm": True}
        assert tool("bus_exec", req)["isError"] and not count_file.exists()
        report["checks"]["unapproved_no_execution"] = True
        run(
            [
                "docker",
                "exec",
                name,
                "douforge",
                "--config",
                "/config/config.json",
                "--state",
                "/data",
                "approve",
                plan["plan_id"],
                "--yes",
            ]
        )
        first = tool("bus_exec", req)
        if first.get("isError") or not first.get("structuredContent", {}).get("ok"):
            report["execution_failure"] = first
            raise RuntimeError("Container SSH failed; see private verification report")
        body = first["structuredContent"]
        actual = json.loads(body["results"][0]["stdout"])
        assert actual["hostname"] == run(["hostname"])
        assert count_file.read_text().splitlines() == ["snapshot"]
        report["checks"]["real_host_snapshot"] = True
        report["host_snapshot"] = actual
        replay = tool("bus_exec", req)["structuredContent"]
        assert replay["replayed"] and replay["results"] == body["results"]
        run(["docker", "restart", "--time", "5", name])
        ready()
        assert (
            tool("bus_receipt", {"request_id": req["request_id"]})["structuredContent"]["status"]
            == "completed"
        )
        replay = tool("bus_exec", req)["structuredContent"]
        assert replay["replayed"] and replay["results"] == body["results"]
        assert tool("bus_exec", {**req, "request_id": "do-not-execute-twice"})["isError"]
        assert count_file.read_text().splitlines() == ["snapshot"]
        report["checks"]["restart_replay_exactly_one_host_invocation"] = True
        # A second, unapproved key cannot authenticate to the temporary daemon.
        rogue = client / "unapproved"
        generated_keys.append(rogue)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(rogue)])
        os.chown(rogue, uid, uid)
        # Separate configuration ensures no valid identity can be offered.
        rejected = subprocess.run(
            [
                "docker",
                "exec",
                name,
                "ssh",
                "-F",
                "/dev/null",
                "-p",
                str(port),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "HostKeyAlias=host-acceptance",
                "-o",
                "UserKnownHostsFile=/home/douforge/.ssh/known_hosts",
                "-i",
                "/home/douforge/.ssh/unapproved",
                "root@" + gateway,
                "service_snapshot",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert rejected.returncode == 255 and "Permission denied" in rejected.stderr
        report["checks"]["wrong_ssh_key_rejected"] = True
        forbidden = subprocess.run(
            [
                "docker",
                "exec",
                name,
                "ssh",
                "-F",
                "/home/douforge/.ssh/config",
                "-o",
                "BatchMode=yes",
                "host-acceptance",
                "unsupported_operation",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert forbidden.returncode == 126
        report["checks"]["target_forced_command_rejects_other_operations"] = True
        info = json.loads(run(["docker", "inspect", name]))[0]
        assert info["Config"]["User"] == "10001:10001" and info["HostConfig"]["ReadonlyRootfs"]
        assert "ALL" in info["HostConfig"]["CapDrop"] and not info["HostConfig"]["Privileged"]
        assert not any("docker.sock" in x["Source"] for x in info["Mounts"])
        report["checks"]["nonroot_readonly_no_docker_socket"] = True
        report["host_invocations"] = len(count_file.read_text().splitlines())
        report["passed"] = report["host_invocations"] == 1
    finally:
        if container_created:
            subprocess.run(["docker", "stop", "--time", "5", name], capture_output=True, timeout=15)
            subprocess.run(["docker", "rm", name], capture_output=True, timeout=15)
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        ssh_log.close()
        for key in generated_keys:
            key.unlink(missing_ok=True)
        (work / "authorized_keys").unlink(missing_ok=True)
        (work / "preview.token").unlink(missing_ok=True)
        report["temporary_private_keys_removed"] = all(not p.exists() for p in generated_keys)
        report["isolated_sshd_stopped"] = daemon is None or daemon.poll() is not None
        report["test_container_removed"] = (
            subprocess.run(["docker", "inspect", name], capture_output=True, timeout=10).returncode != 0
        )
        after = set(run(["docker", "ps", "--format", "{{.ID}}"]).splitlines())
        report["prior_running_containers_preserved"] = prior <= after
        report["prior_running_container_count"] = len(prior)
        report["passed"] = report["passed"] and all(
            report[k]
            for k in [
                "temporary_private_keys_removed",
                "isolated_sshd_stopped",
                "test_container_removed",
                "prior_running_containers_preserved",
            ]
        )
        (work / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
