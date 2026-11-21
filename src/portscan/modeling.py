"""Training, evaluation and persistence of the port scan detection models.

Three supervised classifiers are compared, as designed in Chapter Three:
Random Forest (100 trees), Decision Tree and K-Nearest Neighbours (K = 5,
with standardised features). Because port scans make up under 2% of the
duplicate-free data, Random Forest and Decision Tree use balanced class
weights, and models are compared on F1-score rather than accuracy.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from . import config


def build_models() -> dict[str, object]:
    """The three candidate models with the settings from Chapter Three."""
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=config.RF_N_ESTIMATORS, class_weight="balanced",
            random_state=config.RANDOM_STATE, n_jobs=-1),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=config.RANDOM_STATE),
        "K-Nearest Neighbours": Pipeline([
            ("scaler", StandardScaler()),
            ("knn", KNeighborsClassifier(n_neighbors=config.KNN_K, n_jobs=-1)),
        ]),
    }


def split(X: pd.DataFrame, y: pd.Series):
    """Stratified 80:20 split, so both sets keep the same class balance."""
    return train_test_split(X, y, test_size=config.TEST_SIZE, stratify=y,
                            random_state=config.RANDOM_STATE)


def evaluate(y_true, y_pred) -> dict[str, float]:
    """Accuracy, precision, recall, F1-score, false positive rate and the
    confusion matrix counts (port scan is the positive class)."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def train_and_evaluate(model, X_train, y_train, X_test, y_test) -> tuple[object, dict]:
    """Fit a fresh copy of the model and score it on the test set, with timings."""
    model = clone(model)
    start = time.perf_counter()
    model.fit(X_train, y_train)
    train_s = time.perf_counter() - start
    start = time.perf_counter()
    y_pred = model.predict(X_test)
    predict_s = time.perf_counter() - start
    metrics = evaluate(y_test, y_pred)
    metrics.update(train_seconds=train_s, predict_seconds=predict_s,
                   predict_ms_per_1000_flows=1000 * predict_s / len(X_test) * 1000)
    return model, metrics


def cross_validate(model, X, y, folds: int = config.CV_FOLDS) -> pd.DataFrame:
    """Stratified k-fold scores, one row per fold."""
    rows = []
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=config.RANDOM_STATE)
    for i, (tr, te) in enumerate(skf.split(X, y), start=1):
        fitted = clone(model).fit(X.iloc[tr], y.iloc[tr])
        rows.append({"fold": i, **evaluate(y.iloc[te], fitted.predict(X.iloc[te]))})
    return pd.DataFrame(rows)


def out_of_fold_predictions(model, X, y, folds: int = config.CV_FOLDS) -> np.ndarray:
    """Predict every record with a model that never saw it during training."""
    pred = np.zeros(len(X), dtype=int)
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=config.RANDOM_STATE)
    for tr, te in skf.split(X, y):
        pred[te] = clone(model).fit(X.iloc[tr], y.iloc[tr]).predict(X.iloc[te])
    return pred


def select_best(results: dict[str, dict]) -> str:
    """Highest F1-score; ties broken by higher recall, then lower false positive rate."""
    return max(results, key=lambda m: (round(results[m]["f1"], 6),
                                       round(results[m]["recall"], 6),
                                       -results[m]["fpr"]))


def save_model(model, name: str, metrics: dict, extra: dict | None = None) -> None:
    """Save the chosen model and a metadata file describing it."""
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, config.MODEL_PATH)
    metadata = {
        "model_name": name,
        "features": config.FEATURES,
        "class_names": {str(k): v for k, v in config.CLASS_NAMES.items()},
        "test_metrics": {k: float(v) for k, v in metrics.items()},
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scikit_learn_version": sklearn.__version__,
        "dataset": config.RAW_DATASET_NAME,
        **(extra or {}),
    }
    config.MODEL_METADATA_PATH.write_text(json.dumps(metadata, indent=2))


def load_model():
    """Load the saved model and its metadata (used by the dashboard)."""
    model = joblib.load(config.MODEL_PATH)
    metadata = json.loads(config.MODEL_METADATA_PATH.read_text())
    return model, metadata
