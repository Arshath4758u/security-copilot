# Security Copilot (prototype)

An AI assistant for a security team, built to learn the SOC workflow. **All data is simulated. Jira is a mock unless you configure real credentials.** It is a learning prototype, not a production system.

## Modules
1. **Alert triage agent**: enriches an alert (known-bad IP list, user context), retrieves the matching runbook and MITRE ATT&CK text with RAG (FAISS + Ollama embeddings), and asks a local LLM (Llama 3 via Ollama) for structured JSON: severity, MITRE technique, summary, action, confidence, false-positive flag. Pydantic validates the JSON and the call is retried on failure.
2. **Guardrails + human approval**: plain code (not the LLM) raises severity for known-bad IPs, treats the approved scanner as a false positive, forces human review when alert text tries to talk to the AI, and sends high/critical or low-confidence alerts to an analyst. Nothing is actioned without approval.
3. **Tickets**: mock Jira (JSON file) with status and approval history. Optional real Jira Cloud adapter via environment variables.
4. **Compliance Q&A**: RAG over a sample policy, answers with cited sections, refuses outside the policy, layered prompt-injection defenses.
5. **CI/CD security gate**: scans a repo for secrets (regex, plus gitleaks and pip-audit when installed), redacts findings, has the LLM summarize them, fails the pipeline if anything is found.

## Flow
alert -> enrich -> RAG retrieve -> LLM JSON -> validate -> guardrails -> approval gate -> ticket

## Measured, not claimed
Two labeled test sets: 25 hand-written alerts (varied, tricky) and 100 generated alerts (reproducible with a fixed seed: 66 real threats, 34 false positives, 7 attack categories). `python -m scripts.evaluate --file data/test_alerts.json` reports:
- **False negatives**: real threats the agent called harmless (the dangerous mistake)
- **Missed escalations**: high/critical threats that did not go to a human
- **False positives / false escalations**: harmless alerts treated as threats or sent to an analyst
- technique accuracy, severity accuracy, and a per-category breakdown

Fill in after you run it (the generated set is synthetic and templated, so scores will look better than real life; the hand-written set is the harder test):

| Model | Test set | FP accuracy | False negatives | Missed escalations | False escalations | Technique accuracy |
|---|---|---|---|---|---|---|
| llama3 | 25 hand-written | | | | | |
| llama3 | 100 generated | | | | | |
| llama3.1 | 100 generated | | | | | |

## Prompt-injection defenses (layered, none perfect)
1. Normalizing keyword/regex filter (handles `1gnore` style tricks).
2. Untrusted text wrapped in delimiters and labeled as data in the prompt.
3. JSON schema validation of every LLM reply.
4. Citation check: a "found" answer must cite a retrieved policy section.
5. The LLM can only suggest. Code and humans decide actions. Alert text that looks like an injection is never auto-closed.
`python -m scripts.injection_test` reports how many attacks were blocked.

## Run it
See STEPS.md. Interview preparation is in INTERVIEW_PREP.md.

## Honest limits
- Sample alerts and tickets. No Splunk or CrowdStrike integration. A real integration would follow the same pattern against their APIs.
- Small local model: its confidence scores are rough. That is why guardrails, approval and an evaluation sets exist.
- Evaluation sets (25 hand-written, 100 generated) are small, and the 100 are synthetic and templated. They show direction, not statistical proof.
- Keyword injection filters can be bypassed. The design relies on the other layers too.
- Jira adapter is written to the REST API but only works if you configure credentials.

## Roadmap
Phishing analyzer, vulnerability prioritizer (CVSS + asset context), larger evaluation set, real SIEM alert ingestion.
