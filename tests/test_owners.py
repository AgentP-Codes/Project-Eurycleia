# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Business customers (company owners) and staff records (employee numbers). Simulated data only."""

from pathlib import Path

import pytest

from eurycleia.attacks import lint
from eurycleia.policy import Policy, PolicyError
from eurycleia.vault import Blocked, Vault, company_domain

POLICY = Path(__file__).resolve().parent.parent / "examples" / "business_and_staff.yaml"

ACCOUNTS = {
    7: {"account_id": 7, "company_name": "Harbour Freight Pty Ltd", "domain": "harbourfreight.example",
        "contract_value": "$48,000", "billing_card": "4111 1111 1111 1111"},
    8: {"account_id": 8, "company_name": "Wattle Bakery", "domain": "wattlebakery.example",
        "contract_value": "$3,200", "billing_card": "5555 5555 5555 4444"},
    9: {"account_id": 9, "company_name": "Sole Trader", "domain": "gmail.com",
        "contract_value": "$900", "billing_card": "3782 822463 10005"},
}
STAFF = {
    1001: {"employee_id": 1001, "name": "Mei Lin", "work_email": "mei.lin@acme.example", "salary": "$91,000",
           "leave_days": 12, "tax_file_number": "123 456 782"},
    1002: {"employee_id": 1002, "name": "Sam Ortiz", "work_email": "sam.ortiz@acme.example", "salary": "$78,500",
           "leave_days": 3, "tax_file_number": "876 543 210"},
}


def vault():
    sent = []
    v = Vault(Policy.load(POLICY), {"crm.account": ACCOUNTS.get, "hr.employee": STAFF.get},
              {"email.send": lambda to, subject, body: sent.append((to, body)) or "sent"})
    return v, sent


# ------------------------------------------------------------------ business customers
@pytest.mark.parametrize("to", ["accounts@harbourfreight.example", "Ana Diaz <ana.diaz@harbourfreight.example>",
                                "CFO@HarbourFreight.example"])
def test_anyone_at_the_customers_own_domain_can_get_their_data(to):
    v, sent = vault()
    task = v.start_task("account_support", account_id=7)
    acc = task.read("crm.account")
    task.act("email.send", to=to, subject="Your contract", body=f"{acc['company_name']}: {acc['contract_value']}")
    assert sent and "$48,000" in sent[0][1]


@pytest.mark.parametrize("to", ["x@wattlebakery.example", "x@evil.example", "x@sub.harbourfreight.example",
                                "x@harbourfreight.example.evil.example", "x@harbourfreight.exampl",
                                "x@acme.example.harbourfreight.example.evil"])
def test_other_domains_are_refused(to):
    v, sent = vault()
    task = v.start_task("account_support", account_id=7)
    task.read("crm.account")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="s", body="hello")
    assert sent == []


def test_a_shared_email_service_is_never_a_company_domain():
    v, sent = vault()
    task = v.start_task("account_support", account_id=9)
    task.read("crm.account")
    with pytest.raises(Blocked):
        task.act("email.send", to="anyone@gmail.com", subject="s", body="hi")
    assert sent == []


def test_one_customers_data_cannot_go_to_another_customers_domain():
    v, sent = vault()
    task = v.start_task("account_support", account_id=7)
    acc = task.read("crm.account")
    with pytest.raises(Blocked):     # the recipient check and the owner check both refuse this
        task.act("email.send", to="x@wattlebakery.example", subject="s", body=acc["contract_value"])
    assert sent == []


def test_the_card_placeholder_is_refused_for_email():
    v, sent = vault()
    task = v.start_task("account_support", account_id=7)
    acc = task.read("crm.account")
    with pytest.raises(Blocked):
        task.act("email.send", to="ap@harbourfreight.example", subject="s", body=acc["billing_card"])


@pytest.mark.parametrize("value,expected", [
    ("harbourfreight.example", "harbourfreight.example"), ("@HarbourFreight.Example.", "harbourfreight.example"),
    ("gmail.com", None), ("outlook.com.au", None), ("localhost", None), ("*.example", None),
    ("a b.example", None), ("x@y.example", None), (None, None), (42, None), ("härbour.example", None),
])
def test_company_domain_accepts_only_plain_company_domains(value, expected):
    assert company_domain(value) == expected


# ------------------------------------------------------------------ staff records
def test_an_employee_gets_their_own_details():
    v, sent = vault()
    task = v.start_task("hr_helpdesk", employee_id=1001)
    me = task.read("hr.employee")
    assert "tax_file_number" not in me
    body = f"You have {me['leave_days']} days; {me['salary']}"
    task.act("email.send", to=me["work_email"], subject="Leave", body=body)
    assert sent[0][0] == "mei.lin@acme.example"


def test_an_employees_details_do_not_go_to_colleagues():
    v, sent = vault()
    task = v.start_task("hr_helpdesk", employee_id=1001)
    me = task.read("hr.employee")
    with pytest.raises(Blocked):     # the task only emails the employee themselves
        task.act("email.send", to="sam.ortiz@acme.example", subject="FYI", body=f"Mei earns {me['salary']}")
    assert sent == []


def test_share_internally_false_blocks_colleagues_even_where_they_are_allowed():
    import copy

    import yaml
    raw = yaml.safe_load(POLICY.read_text())
    raw["tasks"]["hr_helpdesk"]["sinks"]["email.send"]["allowed_recipients"].append("*@acme.example")
    sent = []
    v = Vault(Policy.from_dict(copy.deepcopy(raw)), {"crm.account": ACCOUNTS.get, "hr.employee": STAFF.get},
              {"email.send": lambda to, subject, body: sent.append((to, body)) or "sent"})
    task = v.start_task("hr_helpdesk", employee_id=1001)
    me = task.read("hr.employee")
    with pytest.raises(Blocked):     # sam is an allowed recipient now, but the salary is mei's
        task.act("email.send", to="sam.ortiz@acme.example", subject="FYI", body=f"Mei earns {me['salary']}")
    task.act("email.send", to="sam.ortiz@acme.example", subject="Hi", body="Team lunch on Friday?")   # no data: fine
    assert len(sent) == 1
    assert any("share_internally" in w for w in lint(Policy.from_dict(raw)))     # and lint says so


def test_an_employee_number_from_the_model_is_never_used():
    v, sent = vault()
    task = v.start_task("hr_helpdesk", employee_id=1001)
    with pytest.raises(Blocked):
        task.read("hr.employee", 1002)
    with pytest.raises(Blocked):
        task.call_tool("get_employee", {"employee_id": "1002"})


# ------------------------------------------------------------------ policy checks
def test_example_policy_is_valid_and_lint_clean_for_recipients():
    warnings = lint(Policy.load(POLICY))
    assert not [w for w in warnings if "recipient" in w]


@pytest.mark.parametrize("change,message", [
    ({"owner_domain": "domain", "owner": "company"}, "owner_domain needs an owner"),
    ({"share_internally": "no"}, "true or false"),
])
def test_bad_owner_settings_are_rejected(change, message):
    import copy

    import yaml
    raw = yaml.safe_load(POLICY.read_text())
    src = copy.deepcopy(raw["sources"]["crm.account"])
    src.update(change)
    raw["sources"]["crm.account"] = src
    if change.get("owner") == "company":
        raw["tasks"].pop("account_support")
        raw["tools"].pop("get_account")
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict(raw)


def test_the_quick_start_example_runs_as_documented(tmp_path):
    """docs/quickstart.md step 3: examples/first_task.py next to the support template's policy."""
    import shutil
    import subprocess
    import sys

    from eurycleia.cli import main
    root = Path(__file__).resolve().parent.parent
    assert main(["init", "--template", "support", "--dir", str(tmp_path)]) == 0
    shutil.copy(root / "examples" / "first_task.py", tmp_path)
    out = subprocess.run([sys.executable, "first_task.py"], cwd=tmp_path, capture_output=True, text=True,
                         timeout=60, env={**__import__("os").environ, "PYTHONPATH": str(root)})
    assert out.returncode == 0, out.stderr
    assert "[[vault:card_number:" in out.stdout and "blocked: recipient" in out.stdout
    assert "emails sent to: ['priya@example.com']" in out.stdout
    assert "19 made-up attacks" in (root / "docs" / "quickstart.md").read_text()


def test_a_wildcard_in_a_contact_field_is_not_a_pattern():
    """Review finding: an email on file of '*@gmail.com' made crm.customer:{id}.email allow any gmail address."""
    from demo.world import World
    from eurycleia.vault import Vault as V
    world = World()
    world.customers[12]["email"] = "*@gmail.com"
    import demo.__main__ as d
    v = V(Policy.load(d.POLICY), {"crm.customer": world.get_customer, "docs": world.get_doc,
                                   "inbox.ticket": world.get_ticket},
          {"email.send": world.send_email, "payments.refund": world.refund})
    task = v.start_task("support_reply", customer_id=12)
    task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to="stranger@gmail.com", subject="s", body="hello")
    assert world.outbox == []
