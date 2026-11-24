import json
import random
from pathlib import Path

rng = random.Random(42)  # fixed seed: same 100 cases every run

EXT_IPS = [f"203.0.113.{i}" for i in range(2, 60)] + \
          [f"198.51.100.{i}" for i in range(2, 60)] + \
          [f"192.0.2.{i}" for i in range(2, 60)]  # reserved documentation ranges
INT_IPS = [f"10.0.{a}.{b}" for a in range(1, 9) for b in range(5, 60)]
USERS = ["meena.r", "priya.s", "ravi.k", "arun.m", "divya.t", "karthik.v",
         "sana.f", "john.d", "lakshmi.p", "vikram.n"]
ADMINS = ["admin", "root", "svc-finance", "svc-backup", "domain.admin"]
HOSTS = ["FIN-APP-02", "HR-LAP-14", "FS-01", "DB-03", "WEB-05", "DEV-WS-22"]
FAKE_DOMAINS = ["micros0ft-support.com", "paypa1-secure.net", "hr-payrol1.co",
                "g00gle-docs.org", "amaz0n-verify.com"]
REAL_DOMAINS = ["microsoft.com", "docusign.com", "linkedin.com", "company-hr.com"]
CITIES = [("Chennai", "Frankfurt"), ("Mumbai", "Lagos"), ("Atlanta", "Moscow"),
          ("Bengaluru", "Sao Paulo"), ("Dallas", "Hanoi")]

cases = []


def add(kind, atype, user, ip, desc, expected):
    cases.append({"type": atype, "user": user, "src_ip": ip,
                  "description": desc, "expected": expected, "category": kind})


def exp(fp, tech, sev):
    return {"is_false_positive": fp, "technique": tech, "severity": sev}


# ---- Brute force (T1110): 12 true positives, 8 false positives
for i in range(12):
    n = rng.randint(30, 400)
    mins = rng.randint(1, 10)
    u = rng.choice(ADMINS + USERS)
    success = rng.random() < 0.5
    tail = " followed by a successful login." if success else " with no successful login."
    add("brute_force", "authentication", u, rng.choice(EXT_IPS),
        f"{n} failed logins for user '{u}' from one external IP in {mins} minutes{tail}",
        exp(False, "T1110", "high" if success else "medium"))
for i in range(8):
    n = rng.randint(2, 6)
    u = rng.choice(USERS)
    add("brute_force", "authentication", u, rng.choice(INT_IPS),
        rng.choice([
            f"{n} failed logins over 30 minutes from the office network, then a successful login. User reported forgetting the password.",
            f"{n} failed logins for '{u}' from a known internal workstation after a password change; login then succeeded.",
        ]),
        exp(True, None, "low"))

# ---- Phishing (T1566): 12 true positives, 4 false positives
for i in range(12):
    u = rng.choice(USERS)
    d = rng.choice(FAKE_DOMAINS)
    creds = rng.random() < 0.5
    tail = " The user entered their password on the page." if creds else " The user clicked the link but entered nothing."
    add("phishing", "email", u, rng.choice(INT_IPS),
        f"Email from '{d}' with urgent request to verify account. Look-alike domain.{tail}",
        exp(False, "T1566", "high" if creds else "medium"))
for i in range(4):
    u = rng.choice(USERS)
    d = rng.choice(REAL_DOMAINS)
    add("phishing", "email", u, rng.choice(INT_IPS),
        rng.choice([
            f"User opened a link in an email from '{d}' (verified sender, SPF and DKIM pass) about a scheduled document signature.",
            f"User clicked a link in the company's own phishing-awareness simulation email from the security team.",
        ]),
        exp(True, None, "low"))

# ---- Impossible travel / valid accounts (T1078): 10 TP, 6 FP
for i in range(10):
    u = rng.choice(USERS + ADMINS[:2])
    a, b = rng.choice(CITIES)
    mins = rng.randint(5, 40)
    add("impossible_travel", "authentication", u, rng.choice(EXT_IPS),
        f"Successful login for '{u}' from {a}, then another from {b} {mins} minutes later. No VPN in use.",
        exp(False, "T1078", "high" if u in ADMINS else "medium"))
for i in range(6):
    u = rng.choice(USERS)
    a, b = rng.choice(CITIES)
    add("impossible_travel", "authentication", u, rng.choice(EXT_IPS),
        f"Logins for '{u}' from {a} and {b} within minutes; the second came from the corporate VPN exit node in {b}.",
        exp(True, None, "low"))

# ---- Encoded PowerShell (T1059): 10 TP, 5 FP
for i in range(10):
    u = rng.choice(USERS + ["svc-finance"])
    h = rng.choice(HOSTS)
    add("powershell", "endpoint", u, rng.choice(INT_IPS),
        rng.choice([
            f"Word opened on {h} and launched PowerShell with an encoded command.",
            f"Excel macro on {h} spawned cmd.exe, which ran PowerShell with a base64-encoded payload.",
        ]),
        exp(False, "T1059", "high"))
for i in range(5):
    h = rng.choice(HOSTS)
    add("powershell", "endpoint", "svc-deploy", rng.choice(INT_IPS),
        rng.choice([
            f"PowerShell script run on {h} by the approved software deployment service during the scheduled patch window.",
            f"IT admin ran a signed maintenance script on {h} from the management server under change ticket CHG-{rng.randint(1000, 9999)}.",
        ]),
        exp(True, None, "low"))

# ---- Ransomware (T1486): 8 TP, 4 FP
for i in range(8):
    n = rng.randint(800, 9000)
    mins = rng.randint(2, 10)
    u = rng.choice(["svc-backup", "svc-finance"] + USERS)
    add("ransomware", "endpoint", u, rng.choice(INT_IPS),
        f"{n} files renamed with a .locked extension on {rng.choice(HOSTS)} within {mins} minutes. A ransom note file appeared.",
        exp(False, "T1486", "critical"))
for i in range(4):
    n = rng.randint(1000, 5000)
    add("ransomware", "endpoint", "svc-backup", rng.choice(INT_IPS),
        f"{n} files renamed with a .bak extension on FS-01 by the nightly backup job during its scheduled window.",
        exp(True, None, "low"))

# ---- Privilege change (T1078): 8 TP, 4 FP
for i in range(8):
    u = rng.choice(["dev.intern", "contractor.a", "temp.user"] + USERS)
    hr = rng.choice(["2 AM", "3 AM", "4 AM", "11 PM"])
    add("privilege_change", "identity", u, rng.choice(INT_IPS),
        f"Admin privileges granted to '{u}' at {hr}, outside any change window, with no ticket.",
        exp(False, "T1078", "high"))
for i in range(4):
    u = rng.choice(USERS)
    add("privilege_change", "identity", u, rng.choice(INT_IPS),
        f"Admin privileges granted to '{u}' during the approved change window under ticket CHG-{rng.randint(1000, 9999)}, approved by their manager.",
        exp(True, None, "low"))

# ---- Remote services (T1021): 6 TP, 3 FP
for i in range(6):
    src, dst = rng.sample(HOSTS, 2)
    add("remote_services", "network", rng.choice(USERS), rng.choice(INT_IPS),
        f"RDP session from {src} to {dst}, two machines that have never connected before, at 2 AM.",
        exp(False, "T1021", "medium"))
for i in range(3):
    dst = rng.choice(HOSTS)
    add("remote_services", "network", "svc-admin", rng.choice(INT_IPS),
        f"SSH session from the approved jump host to {dst} during a scheduled maintenance window.",
        exp(True, None, "low"))

assert len(cases) == 100, len(cases)
rng.shuffle(cases)
for n, c in enumerate(cases, start=1):
    c["id"] = f"T-{n:03d}"

Path("data").mkdir(exist_ok=True)
Path("data/test_alerts.json").write_text(json.dumps(cases, indent=2), encoding="utf-8")

fp = sum(c["expected"]["is_false_positive"] for c in cases)
print(f"Wrote {len(cases)} cases: {len(cases) - fp} real threats, {fp} false positives")
