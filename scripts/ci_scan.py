"""AI security gate for CI/CD.
Scans a folder for hardcoded secrets (and vulnerable dependencies if tools are installed),
redacts findings, has the LLM summarize them in plain English, and exits 1 if anything is found.

  python -m scripts.ci_scan <folder> [--no-llm] [--no-external]

Tools used when present on PATH (otherwise the built-in regex scanner still runs):
  gitleaks   -> secrets scanning        pip-audit -> vulnerable Python dependencies
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PATTERNS = {
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Hardcoded credential": re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[=:]\s*['\"][^'\"\s]{6,}['\"]"),
}
SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", "data", "demo_repo"}  # demo_repo = deliberate fake secrets
SKIP_FILES = {"ci_scan.py"}
TEXT_EXT = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".txt", ".cfg", ".ini", ".toml", ".sh", ".md"}


def redact(line):
    """Never send the real secret to the LLM or print it in logs."""
    return re.sub(r"(['\"=:]\s*)[^'\"\s]{6,}", r"\1****", line.strip())[:120]


def scan_regex(root):
    findings = []
    root = Path(root)
    for path in root.rglob("*"):
        if (not path.is_file() or path.name in SKIP_FILES
                or any(p in SKIP_DIRS for p in path.relative_to(root).parts)):
            continue
        if path.suffix.lower() not in TEXT_EXT and path.name != ".env":
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if "nosecret" in line:
                continue
            for name, pat in PATTERNS.items():
                if pat.search(line):
                    findings.append({"file": str(path), "line": n, "type": name,
                                     "snippet": redact(line), "tool": "regex"})
    return findings


def parse_gitleaks(items):
    """gitleaks JSON report -> findings (gitleaks already redacts with --redact)."""
    return [{"file": i.get("File", "?"), "line": i.get("StartLine", 0),
             "type": f"gitleaks: {i.get('RuleID', 'secret')}",
             "snippet": "(redacted by gitleaks)", "tool": "gitleaks"} for i in items or []]


def parse_pip_audit(data):
    """pip-audit JSON -> findings, one per vulnerable package."""
    out = []
    for dep in (data or {}).get("dependencies", []):
        vulns = dep.get("vulns", [])
        if vulns:
            ids = ", ".join(v.get("id", "?") for v in vulns[:3])
            fix = ", ".join(sum((v.get("fix_versions", []) for v in vulns), [])[:2]) or "no fix listed"
            out.append({"file": "requirements.txt", "line": 0, "type": "Vulnerable dependency",
                        "snippet": f"{dep['name']}=={dep.get('version', '?')} ({ids}); fix: {fix}",
                        "tool": "pip-audit"})
    return out


def run_gitleaks(root):
    if not shutil.which("gitleaks"):
        return []
    report = Path(tempfile.mkdtemp()) / "gl.json"
    subprocess.run(["gitleaks", "detect", "--no-git", "--source", str(root), "--redact",
                    "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
                   capture_output=True, timeout=300)
    return parse_gitleaks(json.loads(report.read_text())) if report.exists() else []


def run_pip_audit(root):
    req = Path(root) / "requirements.txt"
    if not shutil.which("pip-audit") or not req.exists():
        return []
    try:
        res = subprocess.run(["pip-audit", "-r", str(req), "-f", "json"],
                             capture_output=True, text=True, timeout=300)
        return parse_pip_audit(json.loads(res.stdout))
    except Exception:
        return []


def scan(root, external=True):
    findings = scan_regex(root)
    if external:
        seen = {(os.path.normpath(f["file"]), f["line"]) for f in findings}
        for f in run_gitleaks(root) + run_pip_audit(root):
            if (os.path.normpath(f["file"]), f["line"]) not in seen:
                findings.append(f)
    return findings


def summarize(findings):
    from pydantic import BaseModel

    from app.llm import chat_json

    class Summary(BaseModel):
        summary: str
        fixes: str

    system = ('You are a DevSecOps assistant. Given redacted scan findings, return ONLY JSON '
              '{"summary": "plain-English risk summary", "fixes": "short numbered fixes"}.')
    lines = "\n".join(f"- {f['type']} in {f['file']}:{f['line']}  ({f['snippet']})" for f in findings)
    return chat_json(system, f"FINDINGS:\n{lines}", Summary)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else "."
    findings = scan(root, external="--no-external" not in sys.argv)
    tools = sorted({f["tool"] for f in findings}) or ["regex"]
    print(f"Scanned '{root}': {len(findings)} finding(s)  [tools: {', '.join(tools)}]")
    for f in findings:
        print(f"  [{f['type']}] {f['file']}:{f['line']}  {f['snippet']}")
    if findings and "--no-llm" not in sys.argv:
        try:
            s = summarize(findings)
            print("\nAI SUMMARY:\n" + s.summary + "\n\nSUGGESTED FIXES:\n" + s.fixes)
        except Exception as e:  # the gate must still work if the LLM is down
            print(f"\n(AI summary unavailable: {e})")
    if findings:
        print("\nSECURITY GATE: FAILED")
        sys.exit(1)
    print("SECURITY GATE: PASSED")


if __name__ == "__main__":
    main()
