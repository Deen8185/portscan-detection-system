"""Tests for model training, evaluation, selection, saving and the baseline."""

import numpy as np
import pandas as pd
import pytest

from portscan import config, modeling
from portscan.baseline import distinct_targets_per_window, threshold_detect


def synthetic(n=400, scan_share=0.1, seed=0):
    """Separable toy data in the shape of the real features."""
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < scan_share).astype(int)
    X = pd.DataFrame(rng.normal(100, 10, (n, len(config.FEATURES))), columns=config.FEATURES)
    # Scans differ on several features, as real scans do (short, small, few packets)
    for feat in config.FEATURES[:6]:
        X.loc[y == 1, feat] = rng.normal(10, 2, int(y.sum()))
    return X, pd.Series(y)


def test_evaluate_counts_and_rates():
    m = modeling.evaluate([0, 0, 0, 1, 1, 1], [0, 0, 1, 1, 1, 0])
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (2, 1, 1, 2)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(1 / 3)


def test_models_match_the_design():
    models = modeling.build_models()
    assert list(models) == ["Random Forest", "Decision Tree", "K-Nearest Neighbours"]
    assert models["Random Forest"].n_estimators == 100
    assert models["Random Forest"].class_weight == "balanced"
    assert models["K-Nearest Neighbours"].named_steps["knn"].n_neighbors == 5


def test_split_is_stratified():
    X, y = synthetic()
    _, _, y_train, y_test = modeling.split(X, y)
    assert len(y_test) == pytest.approx(0.2 * len(y), abs=1)
    assert y_test.mean() == pytest.approx(y_train.mean(), abs=0.02)


@pytest.mark.parametrize("name", ["Random Forest", "Decision Tree", "K-Nearest Neighbours"])
def test_each_model_learns_separable_data(name):
    X, y = synthetic()
    X_tr, X_te, y_tr, y_te = modeling.split(X, y)
    _, m = modeling.train_and_evaluate(modeling.build_models()[name], X_tr, y_tr, X_te, y_te)
    assert m["f1"] > 0.9
    assert m["train_seconds"] >= 0 and m["predict_seconds"] >= 0


def test_select_best_uses_f1_then_recall_then_fpr():
    results = {
        "A": {"f1": 0.95, "recall": 0.99, "fpr": 0.01},
        "B": {"f1": 0.97, "recall": 0.90, "fpr": 0.02},
        "C": {"f1": 0.97, "recall": 0.95, "fpr": 0.03},
        "D": {"f1": 0.97, "recall": 0.95, "fpr": 0.001},
    }
    assert modeling.select_best(results) == "D"


def test_out_of_fold_predictions_cover_every_row():
    X, y = synthetic()
    pred = modeling.out_of_fold_predictions(modeling.build_models()["Decision Tree"], X, y)
    assert len(pred) == len(y) and set(pred) <= {0, 1}


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "m.joblib")
    monkeypatch.setattr(config, "MODEL_METADATA_PATH", tmp_path / "m.json")
    X, y = synthetic()
    model = modeling.build_models()["Decision Tree"].fit(X, y)
    modeling.save_model(model, "Decision Tree", {"f1": 1.0})
    loaded, meta = modeling.load_model()
    assert meta["model_name"] == "Decision Tree"
    assert meta["features"] == config.FEATURES
    assert (loaded.predict(X) == model.predict(X)).all()


def flows_for_baseline():
    rows = [("10.0.0.9", "7/7/2017 13:00", "10.0.0.1", p) for p in range(20, 30)]   # 10 ports in one minute
    rows += [("10.0.0.5", "7/7/2017 13:00", "10.0.0.1", p) for p in (80, 443)]       # normal client
    rows += [("10.0.0.9", "7/7/2017 13:01", "10.0.0.1", 22)]                          # next minute
    return pd.DataFrame(rows, columns=["Source IP", "Timestamp", "Destination IP", "Destination Port"])


def test_distinct_targets_per_window():
    counts = distinct_targets_per_window(flows_for_baseline())
    assert list(counts) == [10] * 10 + [2, 2] + [1]


def test_threshold_flags_only_busy_source_in_its_window():
    flags = threshold_detect(flows_for_baseline(), threshold=5)
    assert list(flags) == [1] * 10 + [0, 0] + [0]
