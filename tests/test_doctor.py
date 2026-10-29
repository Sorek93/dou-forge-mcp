"""Offline doctor tests: no SSH, HTTP, credential reads or state mutations."""
import json

from douforge.config import Config
from douforge.doctor import diagnose
from douforge.cli import main


def result(cfg, state_dir, *, ssh_path="ssh", platform_name="posix"):
    return diagnose(cfg, state_dir, ssh_path=ssh_path, platform_name=platform_name)


def checks(report):
    return {c["name"]: c for c in report["checks"]}


def test_new_operator_cannot_confuse_preflight_with_acceptance(tmp_path):
    report = result(Config({"version": 1}), tmp_path / "not-created")
    assert report["status"] == "offline_preflight_only"
    assert not (tmp_path / "not-created").exists()
    assert all(value is False for value in report["verified"].values())
    assert checks(report)["configured_hosts"]["status"] == "warn"


def test_ssh_absent_fails_preflight(tmp_path):
    report = result(Config({"version": 1}), tmp_path, ssh_path="")
    assert report["status"] == "blocked"
    assert checks(report)["ssh_client_found"]["status"] == "fail"


def test_unsupported_controller_fails(tmp_path):
    report = result(Config({"version": 1}), tmp_path, platform_name="nt")
    assert report["status"] == "blocked"
    assert checks(report)["controller_os"]["status"] == "fail"


def test_missing_explicit_ssh_config_fails(tmp_path):
    cfg = Config({"version": 1, "ssh_config": str(tmp_path / "missing")})
    assert checks(result(cfg, tmp_path))["explicit_ssh_config"]["status"] == "fail"


def test_existing_ssh_config_is_only_inspected(tmp_path):
    ssh_config = tmp_path / "ssh-config"
    ssh_config.write_text("Host example\n  ProxyCommand echo NEVER_EXECUTE\n")
    cfg = Config({"version": 1, "ssh_config": str(ssh_config)})
    assert checks(result(cfg, tmp_path))["explicit_ssh_config"]["status"] == "pass"


def test_insecure_state_directory_is_rejected_without_modification(tmp_path):
    path = tmp_path / "public"
    path.mkdir()
    path.chmod(0o755)
    cfg = Config({"version": 1})
    assert checks(result(cfg, path))["state_permissions"]["status"] == "fail"
    assert path.stat().st_mode & 0o777 == 0o755


def test_state_symlink_rejected(tmp_path):
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    assert checks(result(Config({"version": 1}), link))["state_permissions"]["status"] == "fail"


def test_bad_state_file_rejected(tmp_path):
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    db = path / "state.sqlite3"
    db.write_text("fixture")
    db.chmod(0o644)
    assert checks(result(Config({"version": 1}), path))["state_permissions"]["status"] == "fail"
    assert db.read_text() == "fixture"


def test_no_config_secret_or_command_is_echoed(tmp_path):
    private_command = "echo DOCTOR_MUST_NOT_ECHO_ME"
    cfg = Config({"version": 1, "actions": {"probe": {"command": private_command}}})
    report = result(cfg, tmp_path / "not-created")
    assert private_command not in json.dumps(report)
    assert "DOCTOR_MUST_NOT_ECHO_ME" not in json.dumps(report)


def test_preview_is_not_oauth(tmp_path):
    cfg = Config({"version": 1, "http": {"auth_mode": "preview",
        "issuer_url": "http://127.0.0.1:9384",
        "resource_url": "http://127.0.0.1:9384/mcp",
        "preview_principal": "local"}, "principals": {"local": {}}})
    report = result(cfg, tmp_path / "nonexistent")
    assert report["verified"]["oauth_login"] is False
    assert "local-only" in checks(report)["remote_auth"]["advice"]


def test_jwt_is_not_real_idp_acceptance(tmp_path):
    cfg = Config({"version": 1, "http": {"auth_mode": "jwt",
        "issuer_url": "https://id.example.test", "resource_url": "https://forge.example.test/mcp",
        "jwks_url": "https://id.example.test/jwks"}})
    report = result(cfg, tmp_path / "nonexistent")
    assert report["verified"]["chatgpt_connector"] is False
    assert "real OAuth login" in checks(report)["remote_auth"]["advice"]


def test_doctor_cli_does_not_initialize_state(tmp_path, capsys, monkeypatch):
    path = tmp_path / "config.json"
    state_dir = tmp_path / "private-state"
    path.write_text('{"version":1}')
    monkeypatch.setattr("sys.argv", ["douforge", "--config", str(path),
                                   "--state", str(state_dir), "doctor"])
    code = main()
    report = json.loads(capsys.readouterr().out)
    assert code in {0, 2}  # Controller OpenSSH may be absent on the test runner.
    assert report["status"] in {"offline_preflight_only", "blocked"}
    assert report["verified"]["remote_execution"] is False
    assert not state_dir.exists()
