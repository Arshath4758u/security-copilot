# Runbook: Ransomware and mass file encryption

## Detection
Thousands of files renamed or modified within minutes, new extensions such as .locked, ransom notes appearing.

## Triage questions
Which host and account are involved? Is the activity still running? Which shares are reachable from that host?

## Actions
Isolate the host from the network immediately, disable the account, protect backups, and start the incident response process.

## Escalate when
Always escalate as critical. This needs a human incident commander.
