# MITRE ATT&CK techniques (summary notes)

## T1110 Brute Force
Attackers try many passwords to guess an account's login. Signs: many failed logins from one IP or against one user in a short time, especially followed by a success.

## T1078 Valid Accounts
Attackers use legitimate stolen or guessed credentials. Signs: logins from unusual places, impossible travel between locations, logins at odd hours, privileges granted without approval.

## T1566 Phishing
Attackers send deceptive emails to steal credentials or deliver malware. Signs: look-alike sender domains, urgent language, links to fake login pages.

## T1059 Command and Scripting Interpreter
Attackers run commands through PowerShell, cmd or scripts. Signs: encoded commands, Office applications launching shells, scripts run by unexpected accounts.

## T1486 Data Encrypted for Impact
Ransomware encrypts files so victims cannot use them. Signs: mass file renames, new file extensions, many files modified in minutes, ransom notes.

## T1021 Remote Services
Attackers move between machines using remote login tools such as RDP or SSH. Signs: remote logins between servers that normally do not talk to each other.
