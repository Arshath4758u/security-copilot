"""Enrichment: add context to an alert before the LLM sees it."""
import ipaddress
import json
from pathlib import Path

DATA = Path("data")
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def enrich_alert(alert):
    intel = _load("threat_intel.json")
    users = _load("users.json")
    ip = alert["src_ip"]
    return {
        "ip_internal": is_internal(ip),
        "ip_known_bad": ip in intel["known_bad_ips"],
        "approved_scanner": ip in intel["approved_scanners"],
        "user_context": users.get(alert["user"], {"role": "unknown user"}),
    }
