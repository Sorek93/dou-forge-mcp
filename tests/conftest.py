import json
import pytest
from douforge.service import Forge

@pytest.fixture
def setup(tmp_path):
    raw = {"version": 1, "execution_enabled": True, "hosts": {
        "box": {"ssh_alias": "example-box"}, "other": {"ssh_alias": "other-box"}},
        "actions": {"hostname": {"command": "hostname", "require_approval": True}},
        "principals": {"local": {"hosts": ["box"], "actions": ["hostname", "shell"]},
                       "other": {"hosts": ["other"], "actions": ["hostname"]}}}
    config = tmp_path / "config.json"
    config.write_text(json.dumps(raw))
    calls = []
    async def fake(cfg, host, command):
        calls.append((host, command))
        return {"ok": True, "stdout": "fixture-host\n", "stderr": "", "exit_code": 0}
    forge = Forge(config, tmp_path / "state", runner=fake)
    return forge, raw, config, calls
