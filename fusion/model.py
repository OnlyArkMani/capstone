"""
Part B — the composite trustworthiness score.

A regularised logistic regression over the detector signals plus encoded source
tier, fitted on the labelled corpus. Not a hand-picked weighted sum.

Output convention
-----------------
The model predicts `p_poisoned`. The reported figure is **trustworthiness**:

    trust_percent = 100 * (1 - p_poisoned)

Both are kept, because they answer different questions and confusing them is
easy: an analyst reads trust, the audit log stores risk, and the design's
thresholds are expressed in risk.

Fitting decisions, all from design section 3
--------------------------------------------
* **L2, not L1.** The interaction terms are correlated with their parent features
  by construction, and L1 selects arbitrarily among correlated predictors, which
  would make coefficients unstable across folds and destroy the interpretability
  that motivated choosing logistic regression in the first place.
* **Explicit cost weights, not `class_weight='balanced'`.** The weight should
  encode our stated decision cost (a miss is ~10x a false alarm), not an artefact
  of how many poisoned documents we happened to write. Inverse-frequency
  weighting silently turns corpus composition into a policy decision.
* **Grouped splits.** Poisoned documents come from a handful of templates; if a
  template's instances land in both train and test the model memorises surface
  statistics and every metric inflates.
* **Calibration.** Weighted fitting distorts the output probabilities by design.
  Platt scaling is applied on held-out folds, because the confidence measure
  needs probabilities that mean something.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from .features import FeatureSpec

RANDOM_SEED = 20260915        # design section 9.1
COST_RATIO = 10.0             # C_FN / C_FP, design section 3.7
C_GRID = (0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0)
N_BOOTSTRAP = 200             # design section 4.2, for the confidence interval


@dataclass
class FitReport:
    n_train: int
    n_pos: int
    n_neg: int
    chosen_C: float
    n_features: int
    feature_names: list[str]
    coefficients: dict[str, float]
    intercept: float
    calibrated: bool
    backend: str
    underpowered: bool
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrustModel:
    """Logistic regression over detector signals + tier, with a bootstrap ensemble.

    The bootstrap coefficients are fitted once at training time and persisted.
    At inference they cost 200 dot products over a short vector, which buys the
    interval that the confidence measure's model-stability component needs.
    """

    def __init__(self, spec: FeatureSpec) -> None:
        self.spec = spec
        self._model: Any = None
        self._calibrator: Any = None
        self._scaler_mean: np.ndarray | None = None
        self._scaler_std: np.ndarray | None = None
        self._boot_coefs: np.ndarray | None = None
        self._boot_intercepts: np.ndarray | None = None
        self.backend = "unfitted"
        self.report: FitReport | None = None

    # ---------------- scaling ----------------

    def _fit_scaler(self, X: np.ndarray) -> None:
        """Fit on the training fold ONLY, then persist.

        Fitting the scaler on the full dataset before splitting is the most common
        leakage bug in small-corpus work and would invalidate every number reported.
        """
        self._scaler_mean = X.mean(axis=0)
        std = X.std(axis=0)
        std[std == 0] = 1.0
        self._scaler_std = std

    def _scale(self, X: np.ndarray) -> np.ndarray:
        if self._scaler_mean is None:
            return X
        return (X - self._scaler_mean) / self._scaler_std

    # ---------------- fitting ----------------

    def fit(self, X: np.ndarray, y: np.ndarray, groups: np.ndarray | None = None,
            verbose: bool = True) -> FitReport:
        y = np.asarray(y, dtype=int)
        n_pos, n_neg = int(y.sum()), int((1 - y).sum())
        warnings: list[str] = []
        if n_pos < 60:
            warnings.append(
                f"Only {n_pos} positive instances. Design section 3.3 classes this as "
                f"underpowered; coefficients are indicative and the case taxonomy remains "
                f"the primary control.")
        if n_pos < 10:
            warnings.append("Fewer than 10 positives: cross-validated model selection is "
                            "not meaningful; a fixed regularisation strength is used.")

        self._fit_scaler(X)
        Xs = self._scale(X)
        weights = {0: 1.0, 1: COST_RATIO}

        chosen_C, calibrated = 1.0, False
        try:
            from sklearn.linear_model import LogisticRegression       # noqa: PLC0415
            from sklearn.calibration import CalibratedClassifierCV    # noqa: PLC0415

            self.backend = "sklearn"
            chosen_C = self._select_C(Xs, y, groups) if n_pos >= 10 else 1.0
            base = LogisticRegression(C=chosen_C, class_weight=weights,
                                      solver="lbfgs", max_iter=2000,
                                      random_state=RANDOM_SEED)
            base.fit(Xs, y)
            self._model = base

            # Platt scaling; isotonic overfits below ~200 positives (design 3.8).
            n_cv = min(3, max(2, n_pos))
            if n_pos >= 6:
                try:
                    cal = CalibratedClassifierCV(
                        LogisticRegression(C=chosen_C, class_weight=weights,
                                           solver="lbfgs", max_iter=2000,
                                           random_state=RANDOM_SEED),
                        method="sigmoid", cv=n_cv)
                    cal.fit(Xs, y)
                    self._calibrator = cal
                    calibrated = True
                except Exception as exc:
                    warnings.append(f"calibration skipped: {type(exc).__name__}")
            else:
                warnings.append("too few positives to calibrate; raw scores are uncalibrated")

        except ImportError:
            self.backend = "numpy"
            warnings.append("scikit-learn unavailable; using the numpy IRLS fallback. "
                            "Mechanically equivalent, but no cross-validated C selection "
                            "and no probability calibration.")
            self._model = _NumpyLogit().fit(Xs, y, weights)

        self._fit_bootstrap(Xs, y, chosen_C, weights)

        coefs = self._coefficients()
        self.report = FitReport(
            n_train=len(y), n_pos=n_pos, n_neg=n_neg, chosen_C=chosen_C,
            n_features=X.shape[1], feature_names=list(self.spec.names),
            coefficients={n: round(float(c), 6) for n, c in zip(self.spec.names, coefs)},
            intercept=round(float(self._intercept()), 6), calibrated=calibrated,
            backend=self.backend, underpowered=self.spec.underpowered, warnings=warnings,
        )
        if verbose:
            for w in warnings:
                print(f"[fusion] WARNING: {w}")
        return self.report

    def _select_C(self, X: np.ndarray, y: np.ndarray, groups) -> float:
        from sklearn.linear_model import LogisticRegression      # noqa: PLC0415
        from sklearn.metrics import average_precision_score      # noqa: PLC0415
        from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold  # noqa: PLC0415

        n_splits = min(5, max(2, int(y.sum())))
        splitter = (StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_SEED)
                    if groups is not None else
                    StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_SEED))
        split_args = (X, y, groups) if groups is not None else (X, y)

        best_C, best_score = 1.0, -np.inf
        for C in C_GRID:
            scores = []
            for tr, va in splitter.split(*split_args):
                if len(set(y[tr])) < 2 or len(set(y[va])) < 2:
                    continue
                m = LogisticRegression(C=C, class_weight={0: 1.0, 1: COST_RATIO},
                                       solver="lbfgs", max_iter=2000, random_state=RANDOM_SEED)
                m.fit(X[tr], y[tr])
                scores.append(average_precision_score(y[va], m.predict_proba(X[va])[:, 1]))
            if scores and float(np.mean(scores)) > best_score:
                best_score, best_C = float(np.mean(scores)), C
        return best_C

    def _fit_bootstrap(self, X: np.ndarray, y: np.ndarray, C: float, weights) -> None:
        """Refit on B resamples; the spread of predictions is the model's own uncertainty."""
        rng = np.random.default_rng(RANDOM_SEED)
        coefs, intercepts = [], []
        for _ in range(N_BOOTSTRAP):
            idx = rng.integers(0, len(y), len(y))
            if len(set(y[idx])) < 2:
                continue
            try:
                from sklearn.linear_model import LogisticRegression   # noqa: PLC0415
                m = LogisticRegression(C=C, class_weight=weights,
                                       solver="lbfgs", max_iter=1000,
                                       random_state=RANDOM_SEED)
                m.fit(X[idx], y[idx])
                coefs.append(m.coef_[0]); intercepts.append(m.intercept_[0])
            except ImportError:
                m = _NumpyLogit().fit(X[idx], y[idx], weights)
                coefs.append(m.coef); intercepts.append(m.intercept)
        if coefs:
            self._boot_coefs = np.vstack(coefs)
            self._boot_intercepts = np.asarray(intercepts)

    # ---------------- inference ----------------

    @property
    def fitted(self) -> bool:
        """Whether this instance can actually score. A loaded model reports True."""
        return self._model is not None and self.backend != "unfitted"

    def _coefficients(self) -> np.ndarray:
        return (self._model.coef_[0] if self.backend == "sklearn" else self._model.coef)

    def _intercept(self) -> float:
        return float(self._model.intercept_[0] if self.backend == "sklearn"
                     else self._model.intercept)

    def predict_risk(self, X: np.ndarray) -> np.ndarray:
        """P(poisoned), calibrated where calibration was possible."""
        Xs = self._scale(np.atleast_2d(X))
        if self._calibrator is not None:
            return self._calibrator.predict_proba(Xs)[:, 1]
        if self.backend == "sklearn":
            return self._model.predict_proba(Xs)[:, 1]
        return self._model.predict_proba(Xs)

    def predict_trust_percent(self, X: np.ndarray) -> np.ndarray:
        """Trustworthiness, 0-100. The analyst-facing number."""
        return 100.0 * (1.0 - self.predict_risk(X))

    def risk_interval(self, x: np.ndarray, alpha: float = 0.05) -> tuple[float, float, float]:
        """(lower, point, upper) for P(poisoned), from the bootstrap ensemble.

        The UPPER bound is what the action thresholds are applied to (design
        section 4.5): low confidence widens the interval, raises the upper bound,
        and pushes borderline cases toward Review automatically, with no extra rule.

        Why the interval is re-centred on the point estimate
        ---------------------------------------------------
        The bootstrap ensemble is fitted on UNCALIBRATED logistic models, because
        refitting Platt scaling inside each of 200 resamples is not affordable and
        would be fitted on a handful of positives anyway. The point estimate, in
        contrast, comes from the calibrated model. Taking the interval straight
        from the ensemble's own probabilities therefore produced intervals that
        did not contain the number they were reported against -- risk 0.34 with an
        interval of (0.73, 0.88), which is not a defensible thing to show an
        analyst.

        The bootstrap's job here is to quantify COEFFICIENT uncertainty, and
        calibration is a monotone reparameterisation of the score. So the spread
        is taken in logit space relative to the ensemble's own median and applied
        as an offset to the calibrated point. The width is the bootstrap's; the
        location is the calibrated model's; and lo <= point <= hi holds by
        construction. This is an approximation -- the calibration map is not
        exactly affine in logit space -- and it is recorded as such rather than
        presented as an exact posterior.
        """
        point = float(self.predict_risk(x)[0])
        if self._boot_coefs is None:
            return point, point, point
        xs = self._scale(np.atleast_2d(x))[0]
        logits = self._boot_coefs @ xs + self._boot_intercepts

        median = float(np.median(logits))
        d_lo = float(np.percentile(logits, 100 * alpha / 2)) - median
        d_hi = float(np.percentile(logits, 100 * (1 - alpha / 2))) - median

        eps = 1e-9
        p = min(1.0 - eps, max(eps, point))
        point_logit = math.log(p / (1.0 - p))
        lo = 1.0 / (1.0 + math.exp(-(point_logit + d_lo)))
        hi = 1.0 / (1.0 + math.exp(-(point_logit + d_hi)))
        # d_lo <= 0 <= d_hi by construction, so this only guards float drift.
        return min(lo, point), point, max(hi, point)

    # ---------------- persistence ----------------

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "spec": self.spec, "model": self._model, "calibrator": self._calibrator,
            "scaler_mean": self._scaler_mean, "scaler_std": self._scaler_std,
            "boot_coefs": self._boot_coefs, "boot_intercepts": self._boot_intercepts,
            "backend": self.backend, "report": self.report,
        }
        try:
            import joblib  # noqa: PLC0415
            joblib.dump(payload, path)
        except ImportError:
            import pickle  # noqa: PLC0415
            with path.open("wb") as fh:
                pickle.dump(payload, fh)
        # A readable sidecar, so the fitted model is inspectable without loading it.
        if self.report:
            with path.with_suffix(".json").open("w", encoding="utf-8") as fh:
                json.dump({"report": self.report.to_dict(),
                           "feature_spec": self.spec.to_dict()}, fh, indent=2)
                fh.write("\n")

    @classmethod
    def load(cls, path: Path) -> "TrustModel":
        try:
            import joblib  # noqa: PLC0415
            payload = joblib.load(path)
        except ImportError:
            import pickle  # noqa: PLC0415
            with path.open("rb") as fh:
                payload = pickle.load(fh)
        obj = cls(payload["spec"])
        obj._model = payload["model"]
        obj._calibrator = payload["calibrator"]
        obj._scaler_mean = payload["scaler_mean"]
        obj._scaler_std = payload["scaler_std"]
        obj._boot_coefs = payload["boot_coefs"]
        obj._boot_intercepts = payload["boot_intercepts"]
        obj.backend = payload["backend"]
        obj.report = payload["report"]
        return obj


class _NumpyLogit:
    """Dependency-free weighted logistic regression (IRLS with L2).

    Present so the fusion layer runs where scikit-learn is unavailable. Same
    model, same weights; no cross-validated C selection and no calibration.
    """

    def __init__(self, l2: float = 1.0, max_iter: int = 100, tol: float = 1e-7) -> None:
        self.l2, self.max_iter, self.tol = l2, max_iter, tol
        self.coef: np.ndarray | None = None
        self.intercept: float = 0.0

    def fit(self, X: np.ndarray, y: np.ndarray, weights: dict[int, float]) -> "_NumpyLogit":
        n, d = X.shape
        Xb = np.hstack([np.ones((n, 1)), X])
        w = np.array([weights.get(int(t), 1.0) for t in y], dtype=float)
        beta = np.zeros(d + 1)
        for _ in range(self.max_iter):
            eta = Xb @ beta
            p = 1.0 / (1.0 + np.exp(-np.clip(eta, -30, 30)))
            W = w * p * (1 - p) + 1e-9
            z = eta + (y - p) / (p * (1 - p) + 1e-9)
            reg = np.eye(d + 1) / max(self.l2, 1e-9)
            reg[0, 0] = 0.0                     # never penalise the intercept
            H = Xb.T @ (W[:, None] * Xb) + reg
            g = Xb.T @ (W * z)
            new = np.linalg.solve(H, g)
            if np.max(np.abs(new - beta)) < self.tol:
                beta = new
                break
            beta = new
        self.intercept, self.coef = float(beta[0]), beta[1:]
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        eta = np.atleast_2d(X) @ self.coef + self.intercept
        return 1.0 / (1.0 + np.exp(-np.clip(eta, -30, 30)))
