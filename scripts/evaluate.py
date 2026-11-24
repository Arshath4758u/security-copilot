"""Measure the triage agent on labeled alerts. Works with both test files:

  python -m scripts.evaluate                                  (25 hand-written alerts)
  python -m scripts.evaluate --file data/test_alerts.json     (100 generated alerts)
  python -m scripts.evaluate --file data/test_alerts.json --limit 10     (quick smoke test first!)
  python -m scripts.evaluate --file data/test_alerts.json --model llama3.1

Press Ctrl+C any time: results so far are still summarized and saved.

Key numbers:
  false negatives   = real threats the agent called harmless (the dangerous mistake)
  missed escalation = high/critical threats that did NOT go to a human
  false positives   = harmless alerts the agent treated as threats
  false escalations = harmless alerts sent to a human anyway (wasted analyst time)
"""
import argparse
import json
import re
import time
from collections import defaultdict
from pathlib import Path

HIGH = ("high", "critical")


def technique_id(text):
    m = re.match(r"\s*(T\d{4})", text or "")
    return m.group(1) if m else None


def normalize_expected(e):
    """Accept both label formats (25-alert file and 100-alert file)."""
    fp = e["false_positive"] if "false_positive" in e else e["is_false_positive"]
    sev = e.get("severity")
    escalate = e["escalate"] if "escalate" in e else (sev in HIGH and not fp)
    return {"false_positive": fp, "escalate": escalate,
            "technique": e.get("technique"), "severity": sev}


def pct(x, d):
    return f"{100 * x / d:.0f}%" if d else "n/a"


def compute_metrics(rows):
    n = len(rows)
    ok = [r for r in rows if "error" not in r]
    threats = [r for r in ok if not r["expected"]["false_positive"]]
    benign = [r for r in ok if r["expected"]["false_positive"]]
    must_escalate = [r for r in ok if r["expected"]["escalate"]]
    tech = [r for r in threats if r["expected"]["technique"]]
    sev = [r for r in threats if r["expected"]["severity"]]

    per_cat = defaultdict(lambda: {"n": 0, "fp_correct": 0, "false_negatives": 0})
    for r in ok:
        c = per_cat[r.get("category") or "all"]
        c["n"] += 1
        c["fp_correct"] += r["pred"]["false_positive"] == r["expected"]["false_positive"]
        c["false_negatives"] += (not r["expected"]["false_positive"]) and r["pred"]["false_positive"]

    return {
        "alerts": n,
        "llm_errors": n - len(ok),
        "real_threats": len(threats),
        "harmless": len(benign),
        "false_positive_accuracy": pct(sum(r["pred"]["false_positive"] == r["expected"]["false_positive"] for r in ok), n),
        "false_negatives": f"{sum(r['pred']['false_positive'] for r in threats)} of {len(threats)}",
        "missed_escalations": f"{sum(not r['pred']['escalate'] for r in must_escalate)} of {len(must_escalate)}",
        "false_positives": f"{sum(not r['pred']['false_positive'] for r in benign)} of {len(benign)}",
        "false_escalations": f"{sum(r['pred']['escalate'] for r in benign)} of {len(benign)}",
        "technique_accuracy": pct(sum(r["pred"]["technique"] == r["expected"]["technique"] for r in tech), len(tech)),
        "severity_exact": pct(sum(r["pred"]["severity"] == r["expected"]["severity"] for r in sev), len(sev)),
        "per_category": {k: {"alerts": v["n"], "fp_accuracy": pct(v["fp_correct"], v["n"]),
                             "false_negatives": v["false_negatives"]} for k, v in sorted(per_cat.items())},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="data/eval_alerts.json")
    ap.add_argument("--model")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    from app import llm  # imported here so compute_metrics can be tested without Ollama
    from app.triage import triage_alert
    if args.model:
        llm.CHAT_MODEL = args.model

    alerts = json.loads(Path(args.file).read_text(encoding="utf-8"))[: args.limit]
    rows, start = [], time.time()
    try:
        for a in alerts:
            exp = normalize_expected(a["expected"])
            alert = {k: a[k] for k in ("id", "type", "user", "src_ip", "description")}
            base = {"id": a["id"], "category": a.get("category"), "expected": exp}
            try:
                r = triage_alert(alert, dry_run=True)
            except Exception as e:
                rows.append({**base, "error": str(e)[:100]})
                print(f"{a['id']:7} ERROR {str(e)[:60]}")
                continue
            t = r["triage"]
            pred = {"escalate": r["needs_approval"], "false_positive": t["false_positive"],
                    "technique": technique_id(t["mitre_technique"]), "severity": t["severity"],
                    "confidence": t["confidence"]}
            rows.append({**base, "pred": pred, "description": a["description"]})
            flag = ""
            if pred["false_positive"] and not exp["false_positive"]:
                flag = "  <-- FALSE NEGATIVE (real threat called harmless)"
            elif exp["escalate"] and not pred["escalate"]:
                flag = "  <-- MISSED ESCALATION"
            elif not pred["false_positive"] and exp["false_positive"]:
                flag = "  <-- false positive"
            print(f"{a['id']:7} {t['severity']:9} conf={t['confidence']:.2f} esc={r['needs_approval']!s:5} "
                  f"fp={t['false_positive']!s:5} {t['mitre_technique'][:22]:22}{flag}")
    except KeyboardInterrupt:
        print("\nStopped early; summarizing what finished.")

    elapsed = time.time() - start
    report = {"model": llm.CHAT_MODEL, "file": args.file, **compute_metrics(rows),
              "seconds_per_alert": round(elapsed / max(len(rows), 1), 1), "details": rows}
    out = Path(f"data/eval_report_{llm.CHAT_MODEL.replace(':', '_')}_{Path(args.file).stem}.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n=== RESULTS ===")
    for k in ("model", "file", "alerts", "real_threats", "harmless", "llm_errors", "false_positive_accuracy",
              "false_negatives", "missed_escalations", "false_positives", "false_escalations",
              "technique_accuracy", "severity_exact", "seconds_per_alert"):
        print(f"{k:26}{report[k]}")
    print("\nPer category:")
    for cat, v in report["per_category"].items():
        print(f"  {cat:20} alerts={v['alerts']:<4} fp_accuracy={v['fp_accuracy']:<5} false_negatives={v['false_negatives']}")
    print(f"\nSaved {out}")
    print("Most important: false negatives and missed escalations. Read those rows and ask WHY the agent got them wrong.")


if __name__ == "__main__":
    main()
