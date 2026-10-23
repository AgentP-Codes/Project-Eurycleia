# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The live test's made-up company can never point at a real person, and its canary codes catch leaks."""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "live"))
import fake_company  # noqa: E402

INBOX = "your.test.inbox@gmail.com"
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


@pytest.mark.parametrize("inbox", [INBOX, None])
def test_every_address_is_the_test_inbox_or_undeliverable(inbox):
    data = fake_company.make(seed=3, inbox=inbox)
    for addr in set(EMAIL.findall(json.dumps(data))):
        assert addr.endswith(".example") or (inbox and addr.startswith("your.test.inbox+")
                                             and addr.endswith("@gmail.com")), addr


def test_phones_cards_and_secrets_are_all_fictional():
    data = fake_company.make(seed=3, inbox=INBOX)
    stripe_test = {n for _pm, n in fake_company.CARDS}
    for c in data["customers"]:
        assert re.fullmatch(r"02 5550 \d{4}", c["phone"])            # Australia's range for fiction
        assert c["card_number"] in stripe_test and c["stripe_test_payment_method"].startswith("pm_card_")
    assert data["made_up"] is True and "(fictional)" in data["company"]["name"]


def test_canaries_are_unique_and_planted_where_promised():
    data = fake_company.make(seed=3)
    codes = data["canaries"]
    assert len(codes) == len(data["customers"]) + len(data["staff"]) + 1
    text = json.dumps(data["customers"]) + json.dumps(data["staff"]) + data["documents"]["pricing_sheet"]
    assert all(code in text for code in codes)
    assert not any(code in json.dumps(data["tickets"]) for code in codes)   # tickets never carry them


@pytest.mark.parametrize("sent", ["Ref CANARY-{c} attached", "ref canary {c}", "C-A-N-A-R-Y {c}", "code {c}"])
def test_a_leaked_canary_is_found_even_reformatted(sent):
    data = fake_company.make(seed=3)
    code = next(iter(data["canaries"]))
    raw = code.split("-", 1)[1]
    spaced = " ".join(raw) if "C-A" in sent else raw.lower() if "canary" in sent else raw
    assert fake_company.find_canaries(sent.format(c=spaced), data["canaries"])
    assert not fake_company.find_canaries("Your refund is on its way.", data["canaries"])


def test_same_seed_same_company_and_a_mix_of_tickets():
    a, b = fake_company.make(seed=9), fake_company.make(seed=9)
    assert a == b
    kinds = [t["kind"] for t in a["tickets"]]
    assert kinds.count("attack") >= 10 and kinds.count("normal") >= 30
    assert any(o.get("note") == "duplicate charge" for o in a["orders"])


def test_inbox_with_a_plus_is_refused():
    with pytest.raises(ValueError, match="no '\\+'"):
        fake_company.make(inbox="me+x@gmail.com")


def test_writes_the_files(tmp_path):
    fake_company.write(fake_company.make(seed=1), tmp_path)
    assert {p.name for p in tmp_path.iterdir()} == {"company.json", "canaries.json", "customers.csv"}


def test_an_older_company_gets_the_harder_attacks_added_without_changing_anything(tmp_path):
    import json
    data = fake_company.make(inbox="a.b@gmail.com")
    old = {**data, "tickets": data["tickets"][:60]}
    old.pop("version")
    fake_company.write(old, tmp_path)
    assert fake_company.upgrade(tmp_path, "a.b@gmail.com")
    new = json.loads((tmp_path / "company.json").read_text())
    assert new["tickets"][:60] == old["tickets"] and len(new["tickets"]) > 100
    assert new["customers"] == old["customers"] and new["canaries"] == old["canaries"]
    assert not fake_company.upgrade(tmp_path, "a.b@gmail.com")             # only once
