# Runbook: Phishing

## Detection
A user reports or clicks a link in an email with a look-alike sender domain or urgent request.

## Triage questions
Did the user enter credentials on the page? Did others receive the same email? Does the sender domain mimic a real company?

## Actions
Reset the user's password, revoke active sessions, block the sender domain, remove the email from all mailboxes, and warn users.

## Escalate when
Credentials were entered, or the email reached many users.
