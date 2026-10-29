#!/usr/bin/env python3
"""Exercise a prebuilt preview image in a fresh, named Compose project; no production hosts."""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", required=True)
    p.add_argument("--port", type=int, default=19384)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    if not args.project.startswith("douforge-test-"):
        raise ValueError("Use a dedicated douforge-test- project name")
    env = dict(os.environ, DOUFORGE_PORT=str(args.port))
    base = ["docker", "compose", "--project-name", args.project]
    def run(argv):
        return subprocess.run(argv, env=env, check=True, capture_output=True, text=True, timeout=90).stdout.strip()
    if run(base + ["ps", "--all", "--quiet"]):
        raise ValueError("Test project already has containers; refusing to change them")
    cfg = json.loads(run(base + ["config", "--format", "json"]))
    assert cfg["services"]["forge"]["ports"][0]["host_ip"] == "127.0.0.1"
    token = Path("runtime/preview.token").read_text().strip()
    def request(path, data=None, auth=None):
        headers = {"Accept": "application/json, text/event-stream"}
        if auth is not None:
            headers["Authorization"] = "Bearer " + auth
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"http://127.0.0.1:{args.port}"+path,
              data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, {}
    report = {"architecture": platform.machine(), "project": args.project, "checks": {}}
    try:
        run(base + ["up", "--detach", "--no-build", "--wait", "--wait-timeout", "60"])
        status, data = request("/healthz")
        assert status == 200 and data == {"status": "ok"}
        report["checks"]["health"] = True
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "bus_hosts", "arguments": {}}}
        assert request("/mcp", payload)[0] == 401
        assert request("/mcp", payload, "incorrect-test-token")[0] == 401
        status, data = request("/mcp", payload, token)
        assert status == 200
        body = data["result"]
        assert body["structuredContent"]["hosts"] == []
        assert body["structuredContent"]["execution_enabled"] is False
        assert body["content"]
        report["checks"]["auth_and_structured_response"] = True
        container = run(base + ["ps", "--quiet", "forge"])
        info = json.loads(run(["docker", "inspect", container]))[0]
        assert info["Config"]["User"] == "10001:10001"
        assert info["HostConfig"]["ReadonlyRootfs"] is True
        assert "ALL" in info["HostConfig"]["CapDrop"]
        assert info["HostConfig"]["NanoCpus"] == 1000000000
        assert info["HostConfig"]["Memory"] == 384*1024*1024
        assert not info["HostConfig"]["Privileged"]
        assert not info["HostConfig"].get("DeviceRequests")
        assert not any("docker.sock" in x["Source"] for x in info["Mounts"])
        report["checks"]["nonroot_readonly_resource_limits_no_gpu"] = True
        create = "from pathlib import Path;from douforge.state import State;s=State(Path('/data'));print(s.plan('test', {'smoke': True}, 'fixture', 300, 1000)['plan_id'])"
        plan_id = run(base + ["exec", "-T", "forge", "python", "-c", create])
        run(base + ["restart", "forge"])
        for _ in range(40):
            try:
                if request("/healthz")[0] == 200:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.25)
        verify = "from pathlib import Path;from douforge.state import State;import sys;s=State(Path('/data'));assert s.inspect(sys.argv[1])['payload']=={'smoke': True};print('persistent')"
        assert run(base + ["exec", "-T", "forge", "python", "-c", verify, plan_id]) == "persistent"
        report["checks"]["state_survives_restart"] = True
        image = json.loads(run(["docker", "image", "inspect", info["Image"]]))[0]
        assert token not in json.dumps(image)
        report["checks"]["token_not_in_image_metadata"] = True
        report["image"] = {"id": image["Id"], "architecture": image["Architecture"], "size_bytes": image["Size"]}
        report["docker"] = run(["docker", "version", "--format", "{{.Server.Version}}"])
        report["compose"] = run(["docker", "compose", "version", "--short"])
        report["passed"] = True
    finally:
        # Only this explicit test project is stopped; keep its data volume for inspection.
        run(base + ["down", "--timeout", "10"])
        report["test_containers_stopped"] = True
        args.report.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
