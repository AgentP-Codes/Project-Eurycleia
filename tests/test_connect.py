# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""`eurycleia connect / report / enforce / watch / disconnect`."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from demo.__main__ import POLICY as _POLICY
from eurycleia.cli import main
from eurycleia.connect import MARK, ConnectError, connect, disconnect, report, set_mode

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(_POLICY)
FAKE = str(ROOT / "tests" / "fake_mcp_server.py")


@pytest.fixture(autouse=True)
def tv_home(tmp_path, monkeypatch):
    monkeypatch.setenv("EURYCLEIA_HOME", str(tmp_path / "tvhome"))


def claude_config(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "crm": {"command": sys.executable, "args": [FAKE], "env": {"X": "1"}},
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}},
        "otherSetting": True}, indent=2))
    return cfg


def test_connect_wraps_servers_in_watch_mode_and_disconnect_restores_them(tmp_path):
    cfg = claude_config(tmp_path)
    original = json.loads(cfg.read_text())
    names = connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(cfg), servers=["crm"])
    assert names == ["crm"]
    data = json.loads(cfg.read_text())
    crm = data["mcpServers"]["crm"]
    assert MARK in crm["args"] and "--shadow" in crm["args"]
    assert crm["args"][crm["args"].index("--") + 1:] == [sys.executable, FAKE]      # original command kept
    assert crm["env"] == {"X": "1"} and data["otherSetting"] is True                # nothing else touched
    assert data["mcpServers"]["files"] == original["mcpServers"]["files"]           # only the chosen server
    assert (tmp_path / "claude_desktop_config.json.eurycleia-backup").exists()
    assert connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(cfg),
                   servers=["crm"]) == ["crm"]                                        # connecting twice is harmless
    assert json.loads(cfg.read_text())["mcpServers"]["crm"]["args"].count(MARK) == 1

    assert set_mode(True) == ["crm"]
    assert "--shadow" not in json.loads(cfg.read_text())["mcpServers"]["crm"]["args"]
    assert set_mode(False) == ["crm"]
    assert "--shadow" in json.loads(cfg.read_text())["mcpServers"]["crm"]["args"]

    assert disconnect("claude-desktop") == ["crm"]
    assert json.loads(cfg.read_text()) == original


def test_hermes_yaml_settings(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"model": "hermes3", "mcp_servers": {
        "crm": {"command": sys.executable, "args": [FAKE]}}}))
    original = yaml.safe_load(cfg.read_text())
    connect("hermes", POLICY, "support_reply", ["customer_id=12"], config=str(cfg))
    data = yaml.safe_load(cfg.read_text())
    assert MARK in data["mcp_servers"]["crm"]["args"] and data["model"] == "hermes3"
    disconnect("hermes")
    assert yaml.safe_load(cfg.read_text()) == original


@pytest.mark.parametrize("mode", ["watch", "enforce"])
def test_the_rewritten_command_really_protects_the_server(tmp_path, mode):
    """Run the server exactly as the agent app would, from the rewritten settings file."""
    cfg = claude_config(tmp_path)
    audit = tmp_path / "audit.jsonl"
    connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(cfg), servers=["crm"],
            audit=str(audit), enforce=mode == "enforce")
    entry = json.loads(cfg.read_text())["mcpServers"]["crm"]
    outbox = tmp_path / "out.jsonl"
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "send_email", "arguments": {"to": "attacker@evil.example", "subject": "x",
                                                             "body": "hello"}}}]
    p = subprocess.run([entry["command"], *entry["args"]], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                       capture_output=True, text=True, cwd=ROOT, timeout=60,
                       env={**os.environ, **entry.get("env", {}), "FAKE_MCP_OUTBOX": str(outbox)})
    replies = [json.loads(line) for line in p.stdout.splitlines()]
    decisions = [json.loads(line).get("decision") for line in audit.read_text().splitlines()]
    if mode == "enforce":
        assert replies[1]["result"]["isError"] and not outbox.exists() and "block" in decisions
    else:
        assert not replies[1]["result"].get("isError") and "would_block" in decisions
    assert "would have been blocked" in report()


def test_helpful_errors(tmp_path):
    cfg = claude_config(tmp_path)
    for kwargs, msg in [
        (dict(agent="claude-desktop", task="nope", trusted=["customer_id=12"]), "isn't in"),
        (dict(agent="claude-desktop", task="support_reply", trusted=[]), "needs trusted inputs"),
        (dict(agent="claude-desktop", task="support_reply", trusted=["customer_id=12"], servers=["zzz"]),
         "no MCP server"),
        (dict(agent="crewai", task="support_reply", trusted=[]), r"protect\(task\)"),
        (dict(agent="notepad", task="support_reply", trusted=[]), "unknown agent"),
    ]:
        with pytest.raises(ConnectError, match=msg):
            connect(policy=POLICY, config=str(cfg), **kwargs)
    with pytest.raises(ConnectError, match="doesn't exist"):
        connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(tmp_path / "missing.json"))


def test_cli_flow(tmp_path, capsys):
    cfg = claude_config(tmp_path)
    assert main(["connect", "mcp-json", "--config", str(cfg), "--policy", POLICY, "--task", "support_reply",
                 "--trusted", "customer_id=12", "--server", "crm"]) == 0
    out = capsys.readouterr().out
    assert "WATCH" in out and "eurycleia report" in out
    assert main(["report"]) == 0 and "watch mode" in capsys.readouterr().out
    assert main(["enforce"]) == 0 and "enforcing on 1" in capsys.readouterr().out
    assert main(["disconnect"]) == 0 and "restored 1" in capsys.readouterr().out


def test_awkward_settings_files(tmp_path):
    """Found by stress testing: a Windows BOM or broken JSON crashed connect; a private settings file (which can
    hold API keys) became readable by others; a settings file that is a symbolic link was replaced by a copy."""
    import stat
    base = json.loads(claude_config(tmp_path).read_text())
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(base).encode())
    connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(bom), servers=["crm"])
    assert bom.read_bytes().startswith(b"\xef\xbb\xbf")
    disconnect(config=str(bom))
    assert json.loads(bom.read_bytes().decode("utf-8-sig")) == base

    broken = tmp_path / "broken.json"
    broken.write_text('{"mcpServers": {')
    with pytest.raises(ConnectError, match="isn't valid JSON"):
        connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(broken))
    assert broken.read_text() == '{"mcpServers": {'

    if os.name != "nt":
        private = tmp_path / "private.json"
        private.write_text(json.dumps(base))
        private.chmod(0o600)
        connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(private), servers=["crm"])
        assert stat.S_IMODE(private.stat().st_mode) == 0o600
        real = tmp_path / "real.json"
        real.write_text(json.dumps(base))
        link = tmp_path / "link.json"
        link.symlink_to(real)
        connect("claude-desktop", POLICY, "support_reply", ["customer_id=12"], config=str(link), servers=["crm"])
        assert link.is_symlink() and MARK in real.read_text()
        disconnect(config=str(link))
        assert json.loads(real.read_text()) == base
