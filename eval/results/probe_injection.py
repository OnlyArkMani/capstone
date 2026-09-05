import json, glob
from detectors.injection import get_backend
from detectors.base import doc_text  # noqa: F401 (fallback below if not present)

def _doc_text(doc):
    parts = [doc.get("title", ""), doc.get("summary", ""), doc.get("content", "")]
    return "\n\n".join(p for p in parts if p).strip()

clean = {}
for f in glob.glob("corpus/clean/*.json"):
    d = json.load(open(f))
    if "doc_id" in d:
        clean[d["doc_id"]] = d
poisoned = {}
for f in glob.glob("corpus/poisoned/*.json"):
    d = json.load(open(f))
    if "doc_id" in d:
        poisoned[d["doc_id"]] = d

backend = get_backend()
print("backend:", backend.name, "is_model:", getattr(backend, "is_model", None),
      "pos_index:", getattr(backend, "_pos_index", None))
if hasattr(backend, "_model"):
    print("id2label:", dict(backend._model.config.id2label))

results = []
for doc_id, d in {**clean, **poisoned}.items():
    text = _doc_text(d)
    score, detail = backend.score(text)
    results.append((score, doc_id, len(text), detail))

results.sort(reverse=True)
print("\n--- top 6 by score ---")
for score, doc_id, tlen, detail in results[:6]:
    print(f"{score:.4f}  len={tlen:5d}  {doc_id}  logits={detail.get('logits')}")

print("\n--- target document ---")
for score, doc_id, tlen, detail in results:
    if doc_id == "poison-injection-infusion-t3-forum":
        print(f"{score:.4f}  len={tlen:5d}  {doc_id}  logits={detail.get('logits')}")
        d = poisoned[doc_id]
        print("\nfull text fed to model:\n")
        print(_doc_text(d))
