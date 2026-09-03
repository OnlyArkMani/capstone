"""
Detector 1 — embedding anomaly.

K-means over the embeddings of the retrieved documents; each document's score is
its normalised distance from its nearest cluster centre. Per design section 3.2,
the normalisation is a median/MAD robust z-score computed **within the query's
own retrieval set**, which makes the signal scale-free across embedding models
and corpus sizes.

Two things about this detector that are easy to get wrong
---------------------------------------------------------

**Clustering five points is barely clustering.** A retrieval set at k=5 is far
too small for k-means to be stable, and pretending otherwise produces confident
noise. So: below `MIN_DOCS_FOR_KMEANS` the detector does not cluster at all, it
measures distance from the set centroid and says so in `method`. Above it,
k-means runs with a fixed seed and multiple restarts. Either way the *shape* of
the output is the same, so the fusion layer does not branch.

**A poisoned document may not be an outlier here, and that is expected.**
PoisonedRAG documents are constructed to sit near the query in embedding space
-- that is the attack. A document engineered for retrieval proximity can land
comfortably inside the cluster it was aimed at. This detector is therefore
expected to be the *weakest* of the three against this corpus, and a low score
on a poisoned document is a true observation about the attack rather than a bug.
Reading it as a failure would be misreading the experiment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

from .base import BackendInfo, DetectorScore, as_records, doc_text, robust_z, squash

MIN_DOCS_FOR_KMEANS = 4
RANDOM_SEED = 20260915  # design section 9.1
N_INIT = 10


@dataclass(frozen=True)
class AnomalyScore(DetectorScore):
    pass


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _choose_n_clusters(n: int) -> int:
    """At most three clusters, at least two, never more than n // 2.

    Bounded low deliberately: with a handful of points, more clusters means more
    singleton clusters, and a point that is its own cluster has distance zero --
    the outlier would score as the most normal document in the set.
    """
    return max(2, min(3, n // 2))


def _kmeans_numpy(vectors: np.ndarray, n_clusters: int, seed: int = RANDOM_SEED,
                  n_init: int = N_INIT, max_iter: int = 100) -> tuple[np.ndarray, np.ndarray]:
    """Lloyd's algorithm with k-means++ init. Dependency-free, deterministic.

    sklearn is used when available; this exists so the detector runs in an
    environment without it and produces the same kind of answer.
    """
    rng = np.random.default_rng(seed)
    best_inertia, best_centres, best_labels = np.inf, None, None

    for _ in range(n_init):
        # k-means++ seeding
        centres = [vectors[rng.integers(len(vectors))]]
        for _ in range(n_clusters - 1):
            d2 = np.min(((vectors[:, None, :] - np.array(centres)[None, :, :]) ** 2).sum(-1), axis=1)
            total = d2.sum()
            probs = d2 / total if total > 0 else np.full(len(vectors), 1.0 / len(vectors))
            centres.append(vectors[rng.choice(len(vectors), p=probs)])
        centres = np.array(centres)

        labels = np.zeros(len(vectors), dtype=int)
        for _ in range(max_iter):
            dists = ((vectors[:, None, :] - centres[None, :, :]) ** 2).sum(-1)
            new_labels = dists.argmin(axis=1)
            if np.array_equal(new_labels, labels):
                break
            labels = new_labels
            for c in range(n_clusters):
                members = vectors[labels == c]
                if len(members):
                    centres[c] = members.mean(axis=0)

        inertia = float(((vectors - centres[labels]) ** 2).sum())
        if inertia < best_inertia:
            best_inertia, best_centres, best_labels = inertia, centres.copy(), labels.copy()

    return best_centres, best_labels


def _cluster(vectors: np.ndarray, n_clusters: int) -> tuple[np.ndarray, np.ndarray, str]:
    try:
        from sklearn.cluster import KMeans  # noqa: PLC0415

        km = KMeans(n_clusters=n_clusters, n_init=N_INIT, random_state=RANDOM_SEED).fit(vectors)
        return km.cluster_centers_, km.labels_, "kmeans_sklearn"
    except Exception:
        centres, labels = _kmeans_numpy(vectors, n_clusters)
        return centres, labels, "kmeans_numpy"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def embedding_anomaly_score(
    retrieved_docs: Sequence[Any],
    embedder: Any | None = None,
    vectors: np.ndarray | None = None,
) -> list[AnomalyScore]:
    """Score each retrieved document's distance from its nearest cluster centre.

    Args:
        retrieved_docs: RetrievedRecord objects, dicts, or raw strings.
        embedder: anything with `.encode(list[str]) -> ndarray`. Defaults to the
            pipeline's configured embedder.
        vectors: precomputed embeddings, one row per document. Supply these when
            the caller already has them -- re-embedding for the detector would
            double the cost and, worse, risk using a different model than the
            index, which would make the distances incomparable.

    Returns:
        One AnomalyScore per document, in input order. `.score` is in [0, 1].
        `.detail` carries the raw distance and the robust z, which is what the
        fusion feature encoding actually consumes (design section 3.2).
    """
    docs = as_records(retrieved_docs)
    n = len(docs)
    if n == 0:
        return []

    if vectors is None:
        if embedder is None:
            from pipeline.embeddings import get_embedder  # noqa: PLC0415

            embedder = get_embedder()
        vectors = embedder.encode([doc_text(d) for d in docs], is_query=False)
    vectors = np.asarray(vectors, dtype=float)
    backend_name = getattr(embedder, "name", "precomputed")
    is_model = bool(getattr(embedder, "is_semantic", vectors is not None and embedder is None))
    if embedder is not None:
        is_model = bool(getattr(embedder, "is_semantic", False))

    if n == 1:
        # Design section 3.2: a singleton retrieval carries no anomaly evidence.
        # Returning anything but zero would manufacture a signal from nothing.
        backend = BackendInfo(f"singleton:{backend_name}", is_model, "n=1, no dispersion")
        return [AnomalyScore(docs[0].get("doc_id", "doc_0"), 0.0, backend,
                             {"distance": 0.0, "robust_z": 0.0, "method": "singleton",
                              "is_singleton": True, "n_clusters": 0})]

    if n < MIN_DOCS_FOR_KMEANS:
        centre = vectors.mean(axis=0, keepdims=True)
        distances = np.linalg.norm(vectors - centre, axis=1)
        labels = np.zeros(n, dtype=int)
        method = "centroid_distance"
        n_clusters = 1
    else:
        n_clusters = _choose_n_clusters(n)
        centres, labels, method = _cluster(vectors, n_clusters)
        distances = np.linalg.norm(vectors - centres[labels], axis=1)

    zs = robust_z(distances)
    backend = BackendInfo(f"{method}:{backend_name}", is_model,
                          f"n={n}, clusters={n_clusters}")

    return [
        AnomalyScore(
            doc_id=docs[i].get("doc_id", f"doc_{i}"),
            score=squash(float(zs[i])),
            backend=backend,
            detail={
                "distance": round(float(distances[i]), 6),
                "robust_z": round(float(zs[i]), 6),
                "cluster": int(labels[i]),
                "method": method,
                "n_clusters": n_clusters,
                "is_singleton": False,
            },
        )
        for i in range(n)
    ]


def anomaly_score_max(scores: Sequence[AnomalyScore]) -> float:
    """Set-level aggregate: max, not mean.

    Design section 0.5. One crafted document among four clean ones is the whole
    attack; averaging it away is how the attack survives.
    """
    return max((s.score for s in scores), default=0.0)
