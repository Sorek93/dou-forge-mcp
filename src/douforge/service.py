"""Plan-first authorization and durable at-most-once request claiming."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from .config import ForgeError, load_config
from .runner import run_ssh
from .state import State


class Forge:
    def __init__(self, config_path: Path, state_dir: Path, *, runner=run_ssh):
        self.config_path = config_path
        load_config(config_path)  # Refuse to start on absent/malformed configuration.
        self.state = State(state_dir)
        self.runner = runner
        self.execution_lock = asyncio.Lock()  # One active multi-host request per process.

    def hosts(self, principal: str) -> dict:
        cfg = load_config(self.config_path)
        rights = cfg.rights(principal)
        return {"hosts": [{"alias": name, "tags": cfg.hosts[name].get("tags", [])}
                          for name in rights.get("hosts", [])],
                "actions": rights.get("actions", []), "execution_enabled": cfg.execution_enabled}

    def plan(self, principal: str, hosts: list[str], action: str, command: str = "") -> dict:
        cfg = load_config(self.config_path)
        rights = cfg.rights(principal)
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= cfg.max_hosts:
            raise ForgeError("Invalid host count")
        if any(not isinstance(h, str) or h not in rights.get("hosts", []) for h in hosts):
            raise ForgeError("Host not authorized")
        if len(set(hosts)) != len(hosts):
            raise ForgeError("Duplicate hosts")
        if action not in rights.get("actions", []):
            raise ForgeError("Action not authorized")
        approval = True
        if action == "shell":
            if not cfg.shell_enabled:
                raise ForgeError("Free shell is disabled")
            selected = cfg.validate_command(command)
        else:
            if command:
                raise ForgeError("Named actions cannot override their command")
            selected = cfg.actions[action]["command"]
            approval = cfg.actions[action].get("require_approval", True)
        payload = {"hosts": hosts, "action": action, "command": selected,
                   "timeout_s_per_host": cfg.timeout_s, "output_bytes_per_host": cfg.output_bytes,
                   "execution_enabled": cfg.execution_enabled, "approval_required": approval}
        plan = self.state.plan(principal, payload, cfg.fingerprint, cfg.plan_ttl_s, cfg.max_records)
        plan["requires_operator_approval"] = approval
        return plan

    def approve(self, plan_id: str) -> dict:
        # Intentionally callable only through an operator-local CLI, never an MCP tool.
        cfg = load_config(self.config_path)
        if not cfg.execution_enabled:
            raise ForgeError("Execution disabled")
        return self.state.approve(plan_id, cfg.fingerprint)

    async def execute(self, principal: str, plan_id: str, request_id: str, confirm: bool) -> dict:
        if confirm is not True:
            raise ForgeError("confirm must be true (this is NOT operator approval)")
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request_id):
            raise ForgeError("Invalid request_id")
        cfg = load_config(self.config_path)
        cfg.rights(principal)
        if not cfg.execution_enabled:
            raise ForgeError("Execution disabled")
        if self.execution_lock.locked():
            raise ForgeError("Executor busy; keep the same request_id")
        async with self.execution_lock:
            # Plan state cannot be edited by a tool caller. Configuration binds the exact action/hosts.
            existing = self.state.inspect(plan_id)
            approval = existing["payload"]["approval_required"]
            payload, replay = self.state.claim(principal, plan_id, request_id, cfg.fingerprint,
                                              cfg.max_records, approval)
            if replay is not None:
                return replay
            results = []
            try:
                for host in payload["hosts"]:
                    result = await self.runner(cfg, cfg.hosts[host].get("ssh_alias", host), payload["command"])
                    results.append({"host": host, **result})
            except Exception as exc:
                # Unknown exception strings may contain secrets. Store a non-sensitive type only.
                results.append({"ok": False, "error": type(exc).__name__, "outcome": "uncertain"})
            # CancelledError/process crash deliberately leaves a running receipt; no automatic rerun.
            result = {"request_id": request_id, "plan_id": plan_id,
                      "ok": len(results) == len(payload["hosts"]) and all(r["ok"] for r in results),
                      "results": results, "replayed": False}
            self.state.finish(request_id, result)
            return result

    def receipt(self, principal: str, request_id: str) -> dict:
        load_config(self.config_path).rights(principal)
        return self.state.receipt(principal, request_id)
