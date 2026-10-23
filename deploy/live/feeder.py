# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Send the made-up company's support tickets into the test inbox, as if customers had emailed.

    python feeder.py --count 5                  # the next 5 tickets, now
    python feeder.py --count 20 --every 300     # 20 tickets, one every 5 minutes
    python feeder.py --kind attack --count 3    # only attacks

Each email is sent from the test inbox to itself, with the made-up customer's +address in Reply-To and a
signature (from the feeder-secret) that live.py checks, so only these emails can claim to be a customer.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE))

from live import SIGNATURE_HEADER, TICKET_HEADER, FolderMailbox, Mailbox, Settings, open_mailbox, sign  # noqa: E402


def feed(settings: Settings, mailbox: Mailbox | FolderMailbox, count: int, kind: str = "all", every: float = 0,
         sleep=time.sleep, again: bool = False) -> list[str]:
    secret = settings.secret("feeder-secret")
    data = settings.data
    company = json.loads((data / "company.json").read_text())
    state_path = data / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    if again:                                   # a new round: every ticket can be sent again
        state["fed"] = []
        state["round"] = int(state.get("round", 1)) + 1
    fed = state.setdefault("fed", [])
    todo = [t for t in company["tickets"] if t["ticket_id"] not in fed and (kind == "all" or t["kind"] == kind)]
    sent = []
    for i, t in enumerate(todo[:count]):
        if i and every:
            sleep(every)
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Reply-To"] = settings.inbox, settings.inbox, t["from"]
        msg["Subject"] = t["subject"]
        msg[TICKET_HEADER] = t["ticket_id"]
        msg[SIGNATURE_HEADER] = sign(secret, t["ticket_id"], t["from"])
        msg.set_content(t["body"])
        mailbox.send_message(msg)
        fed.append(t["ticket_id"])
        state_path.write_text(json.dumps(state, indent=2))
        sent.append(t["ticket_id"])
        print(f"sent {t['ticket_id']} ({t['kind']}): {t['subject']}", flush=True)
    return sent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=int(os.environ.get("FEED_COUNT") or 1))
    ap.add_argument("--every", type=float, default=0, help="seconds between emails")
    ap.add_argument("--kind", choices=["all", "attack", "normal"], default="all")
    ap.add_argument("--again", action="store_true", default=os.environ.get("FEED_AGAIN") == "1",
                    help="start a new round: send tickets that were already sent, from the first one")
    a = ap.parse_args(argv)
    s = Settings()
    import fake_company
    if (s.data / "company.json").exists() and fake_company.upgrade(s.data, s.inbox):
        print("added the harder attacks to the made-up company (everything already there is unchanged)")
    mailbox = open_mailbox(s)
    sent = feed(s, mailbox, a.count, a.kind, a.every, again=a.again)
    where = s.inbox if isinstance(mailbox, Mailbox) else "the agent's mail folder (no-email mode)"
    print(f"{len(sent)} ticket(s) sent to {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
