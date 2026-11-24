# Runbook: Brute force and password guessing

## Detection
Many failed logins for one user or from one IP in a short window, especially followed by a successful login.

## Triage questions
Is the source IP internal or external? Is it a known bad IP? Was there a successful login after the failures? Is the account privileged?

## Actions
Block or rate-limit the source IP, force a password reset, enable multi-factor authentication, and review what the account did after the successful login.

## Likely false positive
A few failed logins over a long period from a known internal network, followed by one success, usually means a user forgot their password. Do not escalate.

## Escalate when
The login succeeded from an external IP, or the account is an administrator.
