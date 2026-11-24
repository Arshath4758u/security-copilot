"""Tickets. By default a mock Jira (JSON file). If JIRA_URL, JIRA_EMAIL, JIRA_TOKEN and
JIRA_PROJECT are set, the same calls ALSO create/comment on a real Jira Cloud issue
(REST API v2). The local record is always kept, so the app works without Jira."""
import base64
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TICKET_FILE = Path("data/tickets.json")


def jira_enabled():
    return all(os.getenv(v) for v in ("JIRA_URL", "JIRA_EMAIL", "JIRA_TOKEN", "JIRA_PROJECT"))


def _jira_request(method, path, payload=None):
    url = os.environ["JIRA_URL"].rstrip("/") + path
    cred = f"{os.environ['JIRA_EMAIL']}:{os.environ['JIRA_TOKEN']}".encode()
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": "Basic " + base64.b64encode(cred).decode(),
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode()
        return json.loads(body) if body else {}


def _read():
    return json.loads(TICKET_FILE.read_text(encoding="utf-8")) if TICKET_FILE.exists() else []


def _write(tickets):
    TICKET_FILE.parent.mkdir(parents=True, exist_ok=True)
    TICKET_FILE.write_text(json.dumps(tickets, indent=2), encoding="utf-8")


def create_ticket(alert, triage, status, reasons):
    tickets = _read()
    ticket = {
        "key": f"SEC-{len(tickets) + 1}",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": status,
        "alert_id": alert["id"],
        "title": f"[{triage['severity'].upper()}] {alert['type']} alert for {alert['user']}",
        "triage": triage,
        "approval_reasons": reasons,
        "history": [],
    }
    if jira_enabled():
        try:
            desc = (f"Alert {alert['id']}: {alert['description']}\n\nSummary: {triage['summary']}\n"
                    f"MITRE: {triage['mitre_technique']}\nRecommended: {triage['recommended_action']}\n"
                    f"Confidence: {triage['confidence']}\nStatus: {status}\nReasons: {reasons}")
            resp = _jira_request("POST", "/rest/api/2/issue", {"fields": {
                "project": {"key": os.environ["JIRA_PROJECT"]},
                "summary": ticket["title"], "description": desc,
                "issuetype": {"name": "Task"}}})
            ticket["jira_key"] = resp.get("key")
        except Exception as e:  # never let Jira problems break triage
            ticket["jira_error"] = str(e)[:200]
    tickets.append(ticket)
    _write(tickets)
    return ticket


def list_tickets(status=None):
    return [t for t in _read() if status is None or t["status"] == status]


def get_ticket(key):
    return next((t for t in _read() if t["key"] == key), None)


def update_ticket(key, status, analyst, note=""):
    tickets = _read()
    for t in tickets:
        if t["key"] == key:
            t["status"] = status
            t["history"].append({
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "analyst": analyst, "status": status, "note": note,
            })
            if t.get("jira_key") and jira_enabled():
                try:
                    _jira_request("POST", f"/rest/api/2/issue/{t['jira_key']}/comment",
                                  {"body": f"{status} by {analyst}. {note}"})
                except Exception as e:
                    t["jira_error"] = str(e)[:200]
            _write(tickets)
            return t
    return None
