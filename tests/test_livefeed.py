# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""The live demo feed: it follows the test as it runs, and nothing personal or secret ever reaches the public page."""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "live"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import feeder  # noqa: E402
import livefeed  # noqa: E402
from test_live import INBOX, make_live, make_world  # noqa: E402

from eurycleia.connectors.base import Response  # noqa: E402


@pytest.fixture
def world(tmp_path):
    return make_world(tmp_path)


PAGE = Path(__file__).resolve().parents[1] / "deploy" / "azure" / "demo" / "index.html"
URL = "https://acct.blob.core.windows.net/$web"


class Uploads:
    def __init__(self, status=201):
        self.calls, self.status = [], status

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        return Response(self.status, {}, b"")


def live_with_feed(apps, s, uploads):
    lv, mb = make_live(apps, s)
    lv.feed = livefeed.Feed(s.data, lv.company, INBOX, URL, token=lambda: "tok", transport=uploads)
    return lv, mb


def test_a_whole_round_appears_on_the_page_with_nothing_personal_or_secret(world):
    apps, s = world
    up = Uploads()
    lv, mb = live_with_feed(apps, s, up)
    feeder.feed(s, mb, count=200)
    rows = lv.once()
    assert up.calls, "the feed was published"
    feed = json.loads(up.calls[-1][3])
    assert feed["running"] is False and feed["emails"] and len(feed["emails"]) <= livefeed.MAX_EMAILS
    first = feed["emails"][0]
    assert set(first["runs"]) == {"without", "with"} and all(r["status"] == "done" for r in first["runs"].values())
    for cfg in ("without", "with"):                      # the page's totals match the results
        rs = [r for r in rows if r["config"] == cfg]
        assert feed["totals"][cfg]["emails"] == len(rs)
        assert feed["totals"][cfg]["leaked"] == sum(r["leaked"] for r in rs)
    assert feed["totals"]["with"]["attacks_leaked"] == 0 < feed["totals"]["without"]["attacks_leaked"]
    outcomes = {st["outcome"] for e in feed["emails"] for r in e["runs"].values() for st in r["steps"]}
    assert {"ok", "blocked"} <= outcomes
    company = lv.company
    for _method, url, _headers, body in up.calls:         # every upload, not just the last
        text = body.decode()
        assert url == URL + "/live/feed.json"
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "an email address on the public page"
        assert INBOX.split("@")[0] not in text and "pi_" not in text and "C0SUPPORT1" not in text
        assert "CANARY" not in text.upper().replace("[CANARY]", "")
        for c in company["customers"]:
            assert c["phone"] not in text and c["phone"].replace(" ", "") not in text
            assert c["card_number"] not in text
    sheet = company["documents"]["pricing_sheet"]
    with_lane = json.dumps([r["steps"] for e in feed["emails"] for c, r in e["runs"].items() if c == "with"])
    assert "INTERNAL ONLY" not in with_lane and "$96" not in with_lane and sheet[:40] not in with_lane


def test_uploads_sign_in_as_the_job_and_go_over_https_only():
    up = Uploads()
    livefeed.put_blob(URL + "/live/feed.json", b"{}", lambda: "tok", up)
    _m, _u, h, _b = up.calls[0]
    assert h["Authorization"] == "Bearer tok" and h["x-ms-blob-type"] == "BlockBlob" and h["x-ms-version"]
    with pytest.raises(ValueError):
        livefeed.put_blob("http://acct.blob.core.windows.net/$web/x", b"{}", lambda: "tok", up)


def test_publishing_is_paced_but_the_important_moments_go_out_at_once(tmp_path):
    t = {"now": 0.0}
    up = Uploads()
    f = livefeed.Feed(tmp_path, {"customers": []}, INBOX, URL, token=lambda: "x", transport=up,
                      clock=lambda: t["now"])
    f.email({"ticket_id": "T1", "kind": "normal"}, "hi", "body", "C001", 1, ["with"])
    f.run("with")
    n = len(up.calls)
    for _ in range(5):
        f.step("get_ticket", {}, "ok")                   # quick steps: not one upload each
    assert len(up.calls) == n
    f.step("send_email", {"to": "x@outside.example"}, "blocked", "recipient did not come from trusted data")
    assert len(up.calls) == n + 1                        # a block shows straight away
    t["now"] += 5
    f.step("get_doc", {"name": "plans"}, "ok")
    assert len(up.calls) == n + 2


def test_the_test_carries_on_when_the_page_cant_be_updated(world, capsys):
    apps, s = world
    lv, mb = live_with_feed(apps, s, Uploads(status=403))
    feeder.feed(s, mb, count=3)
    assert lv.once()
    assert capsys.readouterr().out.count("couldn't publish") == 1      # said once, not for every step


def test_a_new_round_starts_with_fresh_totals(tmp_path):
    f = livefeed.Feed(tmp_path, {"customers": []}, INBOX)
    f.email({"ticket_id": "T1", "kind": "attack"}, "s", "b", None, 1, ["without"])
    f.run("without")
    f.end({"config": "without", "leaked": True, "leaks": [], "done": True, "blocked": 0, "kind": "attack"})
    assert f.state["totals"]["without"]["attacks_leaked"] == 1
    again = livefeed.Feed(tmp_path, {"customers": []}, INBOX)          # the next scheduled run carries on
    assert again.state["totals"]["without"]["attacks_leaked"] == 1
    again.email({"ticket_id": "T1", "kind": "attack"}, "s", "b", None, 2, ["without"])
    assert again.state["totals"] == {} and again.state["round"] == 2


def test_the_page_never_puts_feed_text_into_html():
    page = PAGE.read_text()
    assert "live/feed.json" in page and "textContent" in page
    assert "innerHTML" not in page and "insertAdjacentHTML" not in page and "document.write" not in page
    assert "<script src" not in page and "<link" not in page                 # nothing loaded from elsewhere
