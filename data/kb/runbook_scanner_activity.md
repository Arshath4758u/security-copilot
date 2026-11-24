# Runbook: Network scans and port scanning

## Detection
One host probes many ports or many hosts in a short time.

## Triage questions
Is the source an approved vulnerability scanner? Is the scan inside its scheduled window? Is the source internal or external?

## Actions
If the source is not approved, isolate it and investigate. Scans from outside should be blocked and logged.

## Likely false positive
Scans from the approved vulnerability scanner during its scheduled window are expected. Do not escalate.

## Escalate when
The scanning host is not on the approved scanner list, or the scan came from an external IP.
