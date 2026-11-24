"""Prompt-injection detection (one layer of several; keyword filters alone can be bypassed)."""
import re

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})

PATTERNS = [
    r"\b(ignore|disregard|override|bypass)\b.{0,40}\b(instructions?|rules?|prompt|guidelines?|previous|prior|above|safety)\b",
    r"\bsystem prompt\b",
    r"\b(reveal|show|print|repeat|leak|translate)\b.{0,25}\b(your|the)\b.{0,10}\b(instructions?|prompt)\b",
    r"\byou are now\b",
    r"\bpretend (you|to be)\b",
    r"\bact as\b",
    r"\bdeveloper mode\b",
    r"\bjailbreak\b",
    r"\bno (rules|restrictions|limits)\b",
    r"\bdo anything now\b",
]
_COMPILED = [re.compile(p) for p in PATTERNS]


def normalize(text):
    """Lowercase, undo simple leetspeak (1gnore -> ignore), strip punctuation, collapse whitespace."""
    t = text.lower().translate(_LEET)
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def looks_like_injection(text):
    t = normalize(text)
    return any(p.search(t) for p in _COMPILED)
