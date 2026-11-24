"""Build a big MITRE ATT&CK knowledge-base file from the official public dataset.

  python -m scripts.fetch_mitre                 (downloads ~40 MB, needs internet)
  python -m scripts.fetch_mitre --file enterprise-attack.json     (use a file you already downloaded)
  python -m scripts.fetch_mitre --subtechniques                    (include T1110.001-style entries)

Then re-run:  python test_rag.py   (rebuilds the FAISS index)
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = Path("data/kb/mitre_attack_full.md")


def clean(text, limit=700):
    text = re.sub(r"\(Citation: [^)]*\)", "", text)          # drop citation markers
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)      # markdown links -> text
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit].rsplit(" ", 1)[0] if len(text) > limit else text


def parse_stix(data, subtechniques=False):
    """Return [(technique_id, name, description)] from a STIX bundle."""
    rows = []
    for o in data.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not ext:
            continue
        tid = ext["external_id"]
        if "." in tid and not subtechniques:
            continue
        rows.append((tid, o.get("name", ""), clean(o.get("description", ""))))
    return sorted(rows)


def to_markdown(rows):
    lines = ["# MITRE ATT&CK Enterprise techniques (from the official dataset)", ""]
    for tid, name, desc in rows:
        lines += [f"## {tid} {name}", desc, ""]
    return "\n".join(lines)


def main():
    args = sys.argv[1:]
    if "--file" in args:
        data = json.loads(Path(args[args.index("--file") + 1]).read_text(encoding="utf-8"))
    else:
        print("Downloading MITRE ATT&CK dataset (about 40 MB)...")
        with urllib.request.urlopen(URL, timeout=120) as r:
            data = json.loads(r.read().decode("utf-8"))
    rows = parse_stix(data, subtechniques="--subtechniques" in args)
    OUT.write_text(to_markdown(rows), encoding="utf-8")
    print(f"Wrote {len(rows)} techniques to {OUT}")
    print("Now run: python test_rag.py   (this rebuilds the index)")


if __name__ == "__main__":
    main()
