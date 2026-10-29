import asyncio
import json
import sqlite3
import sys
import time

import pytest

from douforge.config import Config, ForgeError, load_config
from douforge.runner import run_process, ssh_argv
from douforge.service import Forge
from douforge.state import State


def test_safe_defaults():
    cfg = Config({"version": 1})
    assert not cfg.execution_enabled and not cfg.shell_enabled and not cfg.hosts


@pytest.mark.parametrize("change", [
    {"version": True}, {"version": 2}, {"version": 1, "unknown": True},
    {"version": 1, "execution_enabled": "false"}, {"version": 1, "shell_enabled": 1},
    {"version": 1, "limits": {"timeout_s": 0}}, {"version": 1, "limits": {"timeout_s": 999}},
    {"version": 1, "limits": {"output_bytes": -1}}, {"version": 1, "limits": {"max_hosts": True}},
    {"version": 1, "ssh_config": "relative"}, {"version": 1, "hosts": {"-oProxyCommand=bad": {}}},
    {"version": 1, "hosts": {"good": {"ssh_alias": "box;cmd"}}},
    {"version": 1, "hosts": {"good": {"tags": "not-a-list"}}},
    {"version": 1, "actions": {"a": {"command": ""}}},
    {"version": 1, "actions": {"a": {"command": "a\x00b"}}},
    {"version": 1, "actions": {"a": {"command": "x" * 9000}}},
    {"version": 1, "principals": {"local": {"hosts": ["missing"]}}},
    {"version": 1, "http": {"auth_mode": "none"}},
])
def test_bad_config(change):
    with pytest.raises(ForgeError):
        Config(change)


def test_missing_config(tmp_path):
    with pytest.raises(ForgeError):
        load_config(tmp_path / "missing")


@pytest.mark.parametrize("data", ['{"version":1,"version":1}', "{broken", "null", "[]"])
def test_invalid_json(tmp_path, data):
    path = tmp_path / "bad.json"
    path.write_text(data)
    with pytest.raises(ForgeError):
        load_config(path)


def test_restrict_visible_hosts(setup):
    forge, _, _, _ = setup
    assert [h["alias"] for h in forge.hosts("local")["hosts"]] == ["box"]
    with pytest.raises(ForgeError):
        forge.hosts("stranger")


@pytest.mark.parametrize("hosts,action,cmd", [([], "hostname", ""), (["other"], "hostname", ""),
    (["box", "box"], "hostname", ""), (["box"], "hostname", "echo changed"),
    (["box"], "bad", ""), (["box"], "shell", "echo x")])
def test_denied_plan(setup, hosts, action, cmd):
    forge, _, _, calls = setup
    with pytest.raises(ForgeError):
        forge.plan("local", hosts, action, cmd)
    assert calls == []


def test_plan_never_executes(setup):
    forge, _, _, calls = setup
    plan = forge.plan("local", ["box"], "hostname")
    assert plan["command"] == "hostname" and plan["requires_operator_approval"]
    assert calls == []


def run(coroutine):
    return asyncio.run(coroutine)


def test_confirm_is_not_approval(setup):
    forge, _, _, calls = setup
    plan = forge.plan("local", ["box"], "hostname")
    with pytest.raises(ForgeError, match="approval"):
        run(forge.execute("local", plan["plan_id"], "r1", True))
    assert calls == []


def test_execute_and_replay_after_restart(setup):
    forge, _, config, calls = setup
    plan = forge.plan("local", ["box"], "hostname")
    forge.approve(plan["plan_id"])
    first = run(forge.execute("local", plan["plan_id"], "r1", True))
    new = Forge(config, forge.state.path.parent, runner=forge.runner)
    replay = run(new.execute("local", plan["plan_id"], "r1", True))
    assert first["ok"] and replay["replayed"] and len(calls) == 1
    assert new.receipt("local", "r1")["status"] == "completed"
    with pytest.raises(ForgeError):
        new.receipt("other", "r1")


def test_consumed_plan_cannot_use_new_id(setup):
    forge, _, _, calls = setup
    plan = forge.plan("local", ["box"], "hostname")
    forge.approve(plan["plan_id"])
    run(forge.execute("local", plan["plan_id"], "r1", True))
    with pytest.raises(ForgeError, match="consumed"):
        run(forge.execute("local", plan["plan_id"], "r2", True))
    assert len(calls) == 1


def test_request_id_cannot_change_plan(setup):
    forge, _, _, calls = setup
    p1 = forge.plan("local", ["box"], "hostname")
    p2 = forge.plan("local", ["box"], "hostname")
    forge.approve(p1["plan_id"])
    forge.approve(p2["plan_id"])
    run(forge.execute("local", p1["plan_id"], "r1", True))
    with pytest.raises(ForgeError, match="conflict"):
        run(forge.execute("local", p2["plan_id"], "r1", True))
    assert len(calls) == 1


def test_plan_owner_is_enforced(setup):
    forge, _, _, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    with pytest.raises(ForgeError, match="owned"):
        run(forge.execute("other", p["plan_id"], "r1", True))
    assert calls == []


def test_changed_config_invalidates_approval(setup):
    forge, raw, path, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    raw["actions"]["hostname"]["command"] = "echo changed"
    path.write_text(json.dumps(raw))
    with pytest.raises(ForgeError, match="changed"):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []


def test_invalid_config_fails_closed_after_startup(setup):
    forge, _, path, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    path.write_text("bad")
    with pytest.raises(ForgeError):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []


def test_expired_plan(setup):
    forge, _, _, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    with forge.state.connection() as db:
        db.execute("UPDATE plans SET expires=?", (time.time() - 1,))
    with pytest.raises(ForgeError, match="expired"):
        forge.approve(p["plan_id"])
    assert calls == []


def test_crash_claim_never_reexecutes(setup):
    forge, _, path, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    cfg = load_config(path)
    forge.state.claim("local", p["plan_id"], "r1", cfg.fingerprint, cfg.max_records, True)
    with pytest.raises(ForgeError, match="uncertain"):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []


@pytest.mark.parametrize("confirm,request_id", [(False, "r1"), (1, "r1"), (True, ""),
                                               (True, "bad/request"), (True, "x" * 129)])
def test_bad_execute_args(setup, confirm, request_id):
    forge, _, _, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    with pytest.raises(ForgeError):
        run(forge.execute("local", p["plan_id"], request_id, confirm))
    assert calls == []


def test_disable_execution(setup):
    forge, raw, path, calls = setup
    raw["execution_enabled"] = False
    path.write_text(json.dumps(raw))
    p = forge.plan("local", ["box"], "hostname")
    with pytest.raises(ForgeError, match="disabled"):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []


def test_admin_explicit_autoapproval(setup):
    forge, raw, path, calls = setup
    raw["actions"]["hostname"]["require_approval"] = False
    path.write_text(json.dumps(raw))
    p = forge.plan("local", ["box"], "hostname")
    assert not p["requires_operator_approval"]
    assert run(forge.execute("local", p["plan_id"], "r1", True))["ok"]
    assert len(calls) == 1


def test_shell_always_requires_approval(setup):
    forge, raw, path, calls = setup
    raw["shell_enabled"] = True
    path.write_text(json.dumps(raw))
    p = forge.plan("local", ["box"], "shell", "echo hello")
    assert p["requires_operator_approval"]
    with pytest.raises(ForgeError, match="approval"):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []


def test_state_permissions_and_symlink(tmp_path):
    state = State(tmp_path / "private")
    assert state.path.stat().st_mode & 0o777 == 0o600
    bad = tmp_path / "public"
    bad.mkdir(mode=0o755)
    bad.chmod(0o755)  # Set the intended insecure fixture independently of umask.
    with pytest.raises(ForgeError):
        State(bad)
    link = tmp_path / "link"
    link.symlink_to(state.path.parent)
    with pytest.raises(ForgeError):
        State(link)


def test_plan_capacity(setup):
    forge, raw, path, _ = setup
    raw["limits"] = {"max_records": 10}
    path.write_text(json.dumps(raw))
    for _ in range(10):
        forge.plan("local", ["box"], "hostname")
    with pytest.raises(ForgeError, match="capacity"):
        forge.plan("local", ["box"], "hostname")


def test_ssh_security_options():
    cfg = Config({"version": 1, "ssh_config": "/tmp/operator-config"})
    argv = ssh_argv(cfg, "demo-host", "echo hi; echo there")
    assert "StrictHostKeyChecking=yes" in argv and "ForwardAgent=no" in argv
    assert "PermitLocalCommand=no" in argv and "ControlPath=none" in argv
    assert argv[-3:] == ["--", "demo-host", "echo hi; echo there"]


def test_real_subprocess_bounded_capture():
    result = run(run_process([sys.executable, "-c", "import sys;sys.stdout.write('x'*100000);sys.stderr.write('y'*100000)"],
                   timeout_s=5, output_bytes=1024, hard_output_bytes=1000000))
    assert result["ok"] and result["truncated"]
    assert result["captured_bytes"] == 1024
    assert result["bytes_out"] + result["bytes_err"] == 200000


def test_real_subprocess_hard_limit():
    result = run(run_process([sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x'*8192);sys.stdout.flush()"],
                   timeout_s=5, output_bytes=512, hard_output_bytes=16384))
    assert result["output_limited"] and not result["ok"] and result["captured_bytes"] == 512


def test_real_subprocess_timeout():
    result = run(run_process([sys.executable, "-c", "import time;time.sleep(10)"],
                   timeout_s=0.1, output_bytes=512, hard_output_bytes=16384))
    assert result["timed_out"] and not result["ok"]
    assert not result["remote_termination_verified"]


def test_process_nonzero_and_unicode():
    result = run(run_process([sys.executable, "-c", "print('豆坊');raise SystemExit(3)"],
                   timeout_s=3, output_bytes=512, hard_output_bytes=16384))
    assert not result["ok"] and result["exit_code"] == 3 and "豆坊" in result["stdout"]


def test_runner_failure_has_durable_receipt(setup):
    forge, _, _, _ = setup
    async def broken(*args):
        raise OSError("should-not-be-leaked")
    forge.runner = broken
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    result = run(forge.execute("local", p["plan_id"], "r1", True))
    assert not result["ok"] and "should-not-be-leaked" not in json.dumps(result)
    assert run(forge.execute("local", p["plan_id"], "r1", True))["replayed"]


def test_audit_failure_prevents_execution(setup, monkeypatch):
    forge, _, _, calls = setup
    p = forge.plan("local", ["box"], "hostname")
    forge.approve(p["plan_id"])
    def fail(*a, **kw):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(forge.state, "claim", fail)
    with pytest.raises(sqlite3.OperationalError):
        run(forge.execute("local", p["plan_id"], "r1", True))
    assert calls == []
