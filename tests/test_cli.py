# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
import json
import re

import pytest

from demo.__main__ import POLICY
from demo.world import World
from taskvault import AuditLog, Policy, Vault
from taskvault.attacks import Fixtures, lint, run_attack_suite
from taskvault.cli import main


def gullible_agent(task, inputs):
    """Simulates a model that follows any 'send ... to <address>' instruction it reads."""
    me = task.call_tool("get_customer", {})
    task.call_tool("send_email", {"to": me["email"], "subject": "Re: your ticket", "body": "We're on it."})
    m = re.search(r"send .* to (\S+@\S+?)[.\s]", inputs.get("ticket", ""))
    if m:
        task.call_tool("send_email", {"to": m.group(1), "subject": "export", "body": me["name"]})


def test_attack_suite_catches_a_leaky_policy():
    raw = Policy.load(POLICY).raw
    raw = json.loads(json.dumps(raw))
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"] = ["*"]   # oops
    policy = Policy.from_dict(raw)
    fx = Fixtures(records={"crm.customer": {"12": World().customers[12], "45": World().customers[45]}},
                  trusted={"support_reply": {"customer_id": 12}})
    report = run_attack_suite(policy, fx, ["support_reply"])
    # "*" is a glob matching anyone, but owner checks still stop customer data leaving...
    assert not report.leaks
    assert any("allows any recipient" in w for w in lint(policy))


def test_attack_suite_reports_real_leaks_from_the_oracle():
    raw = {
        "sources": {"crm": {"owner": "cid", "owner_contact": "email",
                            "fields": {"email": "protected", "notes": "normal", "ssn": "protected"}}},
        "tasks": {"t": {"trusted": ["cid"], "reads": {"crm": {"key": "{cid}"}},
                        "sinks": {"webhook.post": {}}}},      # no recipient_arg: data can leave freely
    }
    fx = Fixtures(records={"crm": {"1": {"email": "a@x.example", "ssn": "123-45-6789", "notes": "hi"}}},
                  trusted={"t": {"cid": 1}})
    report = run_attack_suite(Policy.from_dict(raw), fx)
    assert not report.leaks          # the oracle can't see a recipient, so it can't prove a leak...
    assert any("no recipient_arg" in w for w in report.warnings)   # ...but the linter flags the risk


# ---- CLI ----------------------------------------------------------------------

def test_cli_init_check_test(tmp_path, capsys):
    assert main(["init", "--dir", str(tmp_path)]) == 0
    assert main(["init", "--dir", str(tmp_path)]) == 1                   # won't overwrite
    assert main(["check", "--policy", str(tmp_path / "taskvault.yaml")]) == 0
    assert main(["test", "--policy", str(tmp_path / "taskvault.yaml"),
                 "--fixtures", str(tmp_path / "fixtures.yaml")]) == 0
    assert "0 leaked" in capsys.readouterr().out


def test_cli_bad_policy_exit_code(tmp_path, capsys):
    bad = tmp_path / "p.yaml"
    bad.write_text("sources: {crm: {fields: {x: secretish}}}")
    assert main(["check", "--policy", str(bad)]) == 2
    assert "policy error" in capsys.readouterr().err


def test_cli_plan_and_audit(tmp_path, capsys):
    path = tmp_path / "shadow.jsonl"
    world = World()
    vault = Vault(Policy.load(POLICY), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                        "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund},
                  audit=AuditLog(path), mode="shadow")
    t = vault.start_task("support_reply", customer_id=12)
    t.read("crm.customer")
    t.act("email.send", to="audit@acme-billing.example", subject="x", body="y")
    assert main(["report", "--audit", str(path), "--policy", str(POLICY)]) == 0
    assert main(["plan", "--audit", str(path)]) == 0                   # the old name still works
    out = capsys.readouterr().out
    assert "did not come from trusted data" in out and "never used payments.refund" in out
    assert main(["audit", "verify", str(path)]) == 0
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"allow"', '"block"')
    path.write_text("\n".join(lines) + "\n")
    assert main(["audit", "verify", str(path)]) == 1


def test_cli_keys(tmp_path):
    key = tmp_path / "k.key"
    assert main(["keys", "init", str(key)]) == 0 and key.exists()
    assert main(["keys", "shred", str(key)]) == 0 and not key.exists()


@pytest.mark.parametrize("template", ["support", "finance"])
def test_templates_pass_their_own_attack_suite(tmp_path, template):
    main(["init", "--template", template, "--dir", str(tmp_path)])
    report = run_attack_suite(Policy.load(tmp_path / "taskvault.yaml"), Fixtures.load(tmp_path / "fixtures.yaml"))
    assert report.results and not report.leaks and not report.warnings
