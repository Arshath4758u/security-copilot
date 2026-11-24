# Runbook: Account misuse and privilege changes

## Detection
Impossible travel, logins from unusual locations, privileges granted outside a change window or without a ticket.

## Triage questions
Was there an approved change request? Did the user travel or use a VPN? What did the account do after the change?

## Actions
Confirm with the user and their manager, revert unapproved privilege changes, reset credentials, and review recent activity.

## Likely false positive
A VPN or travel explains many location alerts. Confirm with the user before escalating.

## Escalate when
Privileges were changed without approval, or the user cannot confirm the activity.
