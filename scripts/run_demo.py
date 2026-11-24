"""Run all 8 sample alerts through the triage pipeline and print a summary table."""
import json
from pathlib import Path

from app.triage import triage_alert

Path("data/tickets.json").unlink(missing_ok=True)  # fresh demo: tickets restart at SEC-1

SHOULD_NOT_ESCALATE = {"A-1006", "A-1007"}  # deliberate false positives

alerts = json.loads(Path("data/alerts.json").read_text(encoding="utf-8"))
print(f"{'ID':8}{'SEV':10}{'CONF':6}{'FP':6}{'MITRE':28}{'STATUS'}")
passed = True
for a in alerts:
    r = triage_alert(a)
    t = r["triage"]
    print(f"{a['id']:8}{t['severity']:10}{t['confidence']:<6.2f}{str(t['false_positive']):6}"
          f"{t['mitre_technique'][:26]:28}{r['status']}")
    if a["id"] in SHOULD_NOT_ESCALATE and r["needs_approval"]:
        passed = False
        print(f"   ^ {a['id']} should NOT need approval (false positive)")
print("\nFalse-positive check:", "PASS" if passed else "FAIL (tune the prompt or runbooks)")
