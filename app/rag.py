"""RAG over the security knowledge base: chunk -> embed (Ollama) -> FAISS -> search."""
import json
from pathlib import Path

import faiss
import numpy as np
import ollama

KB_DIR = Path("data/kb")
INDEX_DIR = Path("data/index")
EMBED_MODEL = "nomic-embed-text"


def load_chunks():
    """One chunk per '## ' section. The file title is added to each chunk
    so 'Detection' becomes 'Runbook: Phishing / Detection ...' (better retrieval)."""
    chunks = []
    for f in sorted(KB_DIR.glob("*.md")):
        text = f.read_text(encoding="utf-8")
        parts = text.split("\n## ")
        title = parts[0].strip().lstrip("# ").strip()
        for part in parts[1:]:
            part = part.strip()
            if len(part) > 40:
                chunks.append({"source": f.name, "text": f"{title} / {part}"})
    return chunks


def embed(texts, batch=32):
    """Normalized vectors so inner product = cosine similarity. Batched for big knowledge bases."""
    vecs = []
    for i in range(0, len(texts), batch):
        result = ollama.embed(model=EMBED_MODEL, input=texts[i:i + batch])
        vecs.extend(result["embeddings"])
    arr = np.array(vecs, dtype="float32")
    faiss.normalize_L2(arr)
    return arr


def build_index():
    chunks = load_chunks()
    vectors = embed([c["text"] for c in chunks])
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(INDEX_DIR / "kb.faiss"))
    (INDEX_DIR / "chunks.json").write_text(json.dumps(chunks, indent=2), encoding="utf-8")
    return len(chunks)


def search(query, k=3, only=None, exclude=None):
    """Return top-k chunks. `only` / `exclude` filter by file name
    (used to keep the policy out of triage and the runbooks out of Q&A)."""
    index_file = INDEX_DIR / "kb.faiss"
    if not index_file.exists():
        build_index()
    index = faiss.read_index(str(index_file))
    chunks = json.loads((INDEX_DIR / "chunks.json").read_text(encoding="utf-8"))
    scores, ids = index.search(embed([query]), len(chunks))  # rank everything, then filter
    out = []
    for s, i in zip(scores[0], ids[0]):
        if i == -1:
            continue
        c = chunks[i]
        if only and c["source"] != only:
            continue
        if exclude and c["source"] == exclude:
            continue
        out.append({**c, "score": float(s)})
        if len(out) == k:
            break
    return out
