from app.rag import build_index, search

print("Chunks indexed:", build_index())
queries = [
    "50 failed logins from one IP in two minutes",
    "employee clicked a suspicious link in an email",
    "thousands of files renamed with .locked extension",
    "port scan from the vulnerability scanner",
]
for q in queries:
    print("\nQUERY:", q)
    for r in search(q, exclude="compliance_policy.md"):
        print(f"  [{r['score']:.2f}] {r['source']} :: {r['text'][:70]!r}")
