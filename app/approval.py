"""Human approval gate + deterministic guardrails.
The LLM suggests; plain code decides what is allowed to happen automatically."""

CONFIDENCE_THRESHOLD = 0.7
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def apply_guardrails(triage, enrichment):
    """Rules the LLM cannot override. Returns (triage, notes)."""
    notes = []
    sev = triage["severity"]
    if enrichment["ip_known_bad"] and not triage["false_positive"] and SEVERITY_ORDER.index(sev) < 2:
        triage["severity"] = "high"
        notes.append("raised to high: source IP is on the known-bad list")
    if enrichment["approved_scanner"]:
        triage["false_positive"] = True
        notes.append("marked false positive: source is an approved scanner")
    return triage, notes


def needs_human_approval(triage, enrichment):
    """Returns (needs_approval, reasons)."""
    reasons = []
    if triage["severity"] in ("high", "critical"):
        reasons.append(f"severity is {triage['severity']}")
    if triage["confidence"] < CONFIDENCE_THRESHOLD:
        reasons.append(f"confidence {triage['confidence']:.2f} is below {CONFIDENCE_THRESHOLD}")
    if enrichment["ip_known_bad"] and not triage["false_positive"]:
        reasons.append("source IP is on the known-bad list")
    return bool(reasons), reasons


def injection_guard(alert, triage):
    """Alert text is attacker-controlled. If it looks like it is talking to the AI,
    never auto-close it: force human review. Returns (triage, notes)."""
    from app.security import looks_like_injection
    if looks_like_injection(alert["description"]):
        triage["false_positive"] = False
        return triage, ["alert text looks like a prompt-injection attempt; forced to human review"]
    return triage, []
