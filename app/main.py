import json
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app import compliance, rag, tickets
from app.schemas import Alert
from app.triage import triage_alert

app = FastAPI(title="Security Copilot (prototype)")


def _alerts():
    return json.loads(Path("data/alerts.json").read_text(encoding="utf-8"))


class Decision(BaseModel):
    decision: Literal["approve", "reject"]
    analyst: str
    note: Optional[str] = ""


class Question(BaseModel):
    question: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/index/rebuild")
def rebuild():
    return {"chunks_indexed": rag.build_index()}


@app.get("/alerts")
def list_alerts():
    return _alerts()


@app.post("/triage/alert/{alert_id}")
def triage_sample(alert_id: str):
    alert = next((a for a in _alerts() if a["id"] == alert_id), None)
    if not alert:
        raise HTTPException(404, "alert not found")
    return triage_alert(alert)


@app.post("/triage")
def triage_custom(alert: Alert):
    return triage_alert(alert.model_dump())


@app.get("/tickets")
def all_tickets(status: Optional[str] = None):
    return tickets.list_tickets(status)


@app.get("/approvals/pending")
def pending():
    return tickets.list_tickets("Pending Approval")


@app.post("/approvals/{key}")
def decide(key: str, body: Decision):
    t = tickets.get_ticket(key)
    if not t:
        raise HTTPException(404, "ticket not found")
    if t["status"] != "Pending Approval":
        raise HTTPException(409, f"ticket is '{t['status']}', not pending")
    status = "Approved - response authorized (simulated)" if body.decision == "approve" else "Rejected by analyst"
    return tickets.update_ticket(key, status, body.analyst, body.note or "")


@app.post("/compliance/ask")
def ask(q: Question):
    return compliance.ask(q.question)
