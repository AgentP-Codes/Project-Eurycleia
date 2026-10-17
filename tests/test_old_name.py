# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Eurycleia was taskvault before 0.6. Code, settings, folders and connected agents from 0.5 keep working."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import eurycleia
from eurycleia import _names
from eurycleia.connect import connect, disconnect, set_mode

ROOT = Path(__file__).resolve().parent.parent
FAKE = str(ROOT / "tests" / "fake_mcp_server.py")
POLICY = str(ROOT / "demo" / "policy.yaml")


def test_old_imports_are_the_same_modules():
    import taskvault.connect
    from taskvault.errors import TaskvaultError
    from taskvault.integrations import _common

    import eurycleia.integrations._common
    import taskvault
    from taskvault import Vault

    assert Vault is eurycleia.Vault and taskvault.__version__ == eurycleia.__version__
    assert taskvault.connect is eurycleia.connect
    assert _common is eurycleia.integrations._common
    assert TaskvaultError is eurycleia.errors.EurycleiaError


def _run(*args, cwd=ROOT, env=None):
    env = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=cwd, env=env, timeout=60)


def test_python_m_taskvault_still_runs_the_cli():
    for module in ("taskvault", "eurycleia"):
        r = _run("-m", module, "--version")
        assert r.returncode == 0 and r.stdout.strip() == f"eurycleia {eurycleia.__version__}", r.stderr


def test_old_settings_names_are_read(monkeypatch):
    monkeypatch.delenv("EURYCLEIA_MODEL", raising=False)
    monkeypatch.setenv("TASKVAULT_MODEL", "old")
    assert _names.setting("MODEL") == "old"
    monkeypatch.setenv("EURYCLEIA_MODEL", "new")
    assert _names.setting("MODEL") == "new"


def test_home_folder_falls_back_to_the_old_one(tmp_path, monkeypatch):
    for name in ("EURYCLEIA_HOME", "TASKVAULT_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert _names.home_dir() == tmp_path / ".eurycleia"            # a fresh install
    (tmp_path / ".taskvault").mkdir()
    assert _names.home_dir() == tmp_path / ".taskvault"            # only the 0.5 folder: keep using it
    (tmp_path / ".eurycleia").mkdir()
    assert _names.home_dir() == tmp_path / ".eurycleia"
    monkeypatch.setenv("TASKVAULT_HOME", str(tmp_path / "x"))
    assert _names.home_dir() == tmp_path / "x"


def test_cli_finds_an_old_policy_file(tmp_path):
    (tmp_path / "taskvault.yaml").write_text(Path(POLICY).read_text())
    r = _run("-m", "eurycleia", "check", cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "eurycleia.yaml" not in r.stdout + r.stderr


def test_init_writes_the_new_name(tmp_path):
    assert _run("-m", "eurycleia", "init", "--dir", str(tmp_path)).returncode == 0
    assert (tmp_path / "eurycleia.yaml").exists() and not (tmp_path / "taskvault.yaml").exists()


def _connected_by_05(tmp_path):
    """A settings file as taskvault 0.5's `connect` left it, and its record of the connection."""
    home = tmp_path / "tvhome"
    home.mkdir()
    cfg = tmp_path / "claude_desktop_config.json"
    original = {"command": sys.executable, "args": [FAKE]}
    wrapped = {"command": sys.executable,
               "args": ["-m", "taskvault", "serve", "--taskvault-connected", "--policy", POLICY, "--task",
                        "support_reply", "--trusted", "customer_id=12", "--audit", str(home / "audit.jsonl"),
                        "--shadow", "--", sys.executable, FAKE]}
    cfg.write_text(json.dumps({"mcpServers": {"crm": wrapped}}))
    (cfg.parent / (cfg.name + ".taskvault-backup")).write_text(json.dumps({"mcpServers": {"crm": original}}))
    (home / "connections.json").write_text(json.dumps({str(cfg.resolve()): {
        "agent": "claude-desktop", "servers": {"crm": original}, "audit": str(home / "audit.jsonl")}}))
    return cfg, original


def test_agents_connected_by_05_keep_working(tmp_path, monkeypatch):
    monkeypatch.delenv("EURYCLEIA_HOME", raising=False)
    monkeypatch.setenv("TASKVAULT_HOME", str(tmp_path / "tvhome"))
    cfg, original = _connected_by_05(tmp_path)

    # connecting again doesn't wrap twice, and doesn't overwrite the 0.5 backup with a wrapped copy
    assert connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(cfg)) == ["crm"]
    args = json.loads(cfg.read_text())["mcpServers"]["crm"]["args"]
    assert args.count("serve") == 1
    assert not (cfg.parent / (cfg.name + ".eurycleia-backup")).exists()

    assert set_mode(enforce=True) == ["crm"]
    assert "--shadow" not in json.loads(cfg.read_text())["mcpServers"]["crm"]["args"]
    assert disconnect() == ["crm"]
    assert json.loads(cfg.read_text())["mcpServers"]["crm"] == original


def test_mcp_proxy_accepts_the_old_meta_key():
    from eurycleia.mcp import StdioMCPClient
    from tests.test_mcp import _call, _proxy

    client = StdioMCPClient([sys.executable, FAKE])
    try:
        proxy = _proxy(client)
        old_meta = {"taskvault": {"trusted": {"customer_id": 12}}}
        proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "_meta": old_meta}})
        assert "Priya Shah" in _call(proxy, "get_customer")["content"][0]["text"]
    finally:
        client.close()


def test_encryption_labels_are_unchanged():
    """Boxes and keyed audit logs made by taskvault 0.5 must still open: the key labels keep the old name."""
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from eurycleia.audit import audit_key

    class Provider:
        def data_key(self):
            return b"k" * 32

    assert audit_key(Provider()) == HKDF(SHA256(), 32, salt=None, info=b"taskvault-audit-log").derive(b"k" * 32)
    boxes = (ROOT / "eurycleia" / "boxes.py").read_text()
    assert boxes.count('info=b"taskvault-box"') == 2 and 'info=b"taskvault-" + purpose' in boxes


@pytest.mark.parametrize("cmd", ["eurycleia", "eury", "taskvault"])
def test_all_three_commands_are_declared(cmd):
    tomllib = pytest.importorskip("tomllib")       # Python 3.11+
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["scripts"]
    assert scripts[cmd] == "eurycleia.cli:main"
