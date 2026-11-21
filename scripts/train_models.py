"""Phase 2: train, compare and save the port scan detection models.

Run from the project folder (after scripts/prepare_data.py):
    python scripts/train_models.py

Experiments, each saved to reports/tables (CSV) and reports/figures (PNG):
  1. Main comparison of Random Forest, Decision Tree and KNN on the
     duplicate-free data (stratified 80:20 split).
  2. 5-fold cross-validation of all three models; the model with the highest
     mean F1-score is selected and saved.
  3. The same comparison with duplicates kept, to show how they inflate scores.
  4. Feature importance (impurity-based and permutation) of the best model.
  5. Ablation: the best model without the two Init_Win_bytes features.
  6. Single-feature check: how far each feature gets on its own.
  7. Threshold-based baseline compared with the model on every flow.
  8. Slow scan simulation: thinning out scan traffic to mimic a slower scanner.
"""

import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.inspection import permutation_importance
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.tree import DecisionTreeClassifier

from portscan import config
from portscan.baseline import threshold_detect
from portscan.modeling import (build_models, cross_validate, evaluate,
                               out_of_fold_predictions, save_model, select_best,
                               split, train_and_evaluate)
from portscan.plotting import (BENIGN_COLOR, PORTSCAN_COLOR, TEXT_PRIMARY,
                               TEXT_SECONDARY, apply_style, save)
from portscan.preprocessing import TARGET_COLUMN

T, F = config.TABLES_DIR, config.FIGURES_DIR
INIT_WIN = ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]
THRESHOLDS = [2, 3, 5, 10, 15, 20, 30, 50, 100, 200, 500]
SLOWDOWN = [1, 10, 50, 100, 500, 1000]
METRIC_COLS = ["accuracy", "precision", "recall", "f1", "fpr"]


_START = time.perf_counter()


def header(text):
    print(f"\n{'=' * 70}\n{text}   [{time.perf_counter() - _START:.0f}s elapsed]\n{'=' * 70}", flush=True)


def main():
    apply_style()
    data = pd.read_csv(config.PROCESSED_DIR / "model_dataset.csv")
    X, y = data[config.FEATURES], data[TARGET_COLUMN]
    X_train, X_test, y_train, y_test = split(X, y)
    test_set = data.loc[X_test.index]
    test_set.to_csv(config.PROCESSED_DIR / "test_set.csv", index=False)
    print(f"Duplicate-free data: {len(data):,} records | train {len(X_train):,} | test {len(X_test):,} "
          f"| scans in test: {int(y_test.sum())}")

    # ------------------------------------------------------------ 1. main comparison
    header("1. Model comparison (duplicate-free data, 80:20 split)")
    models = build_models()
    fitted, results = {}, {}
    for name, model in models.items():
        fitted[name], results[name] = train_and_evaluate(model, X_train, y_train, X_test, y_test)
    comparison = pd.DataFrame(results).T
    comparison.index.name = "model"
    comparison.to_csv(T / "model_comparison.csv")
    print(comparison[METRIC_COLS + ["tn", "fp", "fn", "tp", "train_seconds", "predict_ms_per_1000_flows"]].round(4).to_string())
    plot_confusion_matrices(results)

    # ------------------------------------------------------------ 2. cross-validation
    header("2. 5-fold stratified cross-validation")
    cv_rows = []
    for name, model in models.items():
        folds = cross_validate(model, X, y)
        folds.insert(0, "model", name)
        cv_rows.append(folds)
    cv = pd.concat(cv_rows, ignore_index=True)
    cv.to_csv(T / "cross_validation_folds.csv", index=False)
    cv_summary = cv.groupby("model")[["precision", "recall", "f1", "fpr"]].agg(["mean", "std"])
    cv_summary.to_csv(T / "cross_validation_summary.csv")
    print(cv_summary.round(4).to_string())
    # The model is chosen on the mean of 5 folds rather than on one split:
    # on 329 test scans a single false alarm can reorder the models.
    cv_means = {name: {m: cv_summary.loc[name, (m, "mean")] for m in ("f1", "recall", "fpr")}
                for name in models}
    best = select_best(cv_means)
    print(f"\nBest model by mean cross-validated F1-score: {best}", flush=True)

    # ------------------------------------------------------------ 3. with duplicates
    header("3. Same comparison with duplicates kept (inflated evaluation)")
    flows = pd.read_csv(config.PROCESSED_DIR / "flows_clean.csv")
    Xd, yd = flows[config.FEATURES], flows[TARGET_COLUMN]
    Xd_train, Xd_test, yd_train, yd_test = split(Xd, yd)
    train_keys = set(map(tuple, Xd_train.values))
    seen = np.array([tuple(r) in train_keys for r in Xd_test.values])
    dup_rows = []
    for name, model in models.items():
        _, m = train_and_evaluate(model, Xd_train, yd_train, Xd_test, yd_test)
        dup_rows.append({"model": name, **{k: m[k] for k in METRIC_COLS + ["fn", "fp"]}})
    dup = pd.DataFrame(dup_rows).set_index("model")
    dup["test_rows"] = len(Xd_test)
    dup["test_rows_identical_to_a_training_row_pct"] = round(100 * seen.mean(), 2)
    dup["test_scans_identical_to_a_training_row_pct"] = round(100 * seen[yd_test.values == 1].mean(), 2)
    dup.to_csv(T / "with_duplicates_comparison.csv")
    print(dup.round(4).to_string())

    # ------------------------------------------------------------ 4. feature importance
    header(f"4. Feature importance ({best})")
    best_model = fitted[best]
    # n_jobs stays at 1: the Random Forest already predicts on every core, and
    # nesting a second layer of worker processes stalls on Windows.
    perm = permutation_importance(best_model, X_test, y_test, scoring="f1", n_repeats=5,
                                  random_state=config.RANDOM_STATE, n_jobs=1)
    imp = pd.DataFrame({"feature": config.FEATURES,
                        "permutation_f1_drop_mean": perm.importances_mean,
                        "permutation_f1_drop_std": perm.importances_std})
    if hasattr(best_model, "feature_importances_"):
        imp["impurity_importance"] = best_model.feature_importances_
    imp = imp.sort_values("permutation_f1_drop_mean", ascending=False)
    imp.to_csv(T / "feature_importance.csv", index=False)
    print(imp.round(4).to_string(index=False))
    plot_feature_importance(imp)

    # ------------------------------------------------------------ 5. ablation
    header("5. Ablation: without the Init_Win_bytes features")
    reduced = [f for f in config.FEATURES if f not in INIT_WIN]
    _, abl = train_and_evaluate(models[best], X_train[reduced], y_train, X_test[reduced], y_test)
    ablation = pd.DataFrame({"All 16 features": results[best], "Without Init_Win_bytes (14 features)": abl}).T
    ablation.to_csv(T / "ablation_init_win.csv")
    print(ablation[METRIC_COLS + ["fn", "fp"]].round(4).to_string())

    # ------------------------------------------------------------ 6. single features
    header("6. Each feature on its own (Decision Tree, 5-fold F1)")
    skf = StratifiedKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=config.RANDOM_STATE)
    single = []
    for feat in config.FEATURES:
        dt = DecisionTreeClassifier(class_weight="balanced", random_state=config.RANDOM_STATE)
        f1s = cross_val_score(dt, X[[feat]], y, cv=skf, scoring="f1")
        single.append({"feature": feat, "f1_mean": f1s.mean(), "f1_std": f1s.std()})
    single = pd.DataFrame(single).sort_values("f1_mean", ascending=False)
    single.to_csv(T / "single_feature_f1.csv", index=False)
    print(single.round(4).to_string(index=False))

    # ------------------------------------------------------------ 7. threshold baseline
    header("7. Threshold-based detection vs the model, on all 286k flows")
    oof = out_of_fold_predictions(models[best], X, y)
    data_oof = data[config.FEATURES + [config.LABEL_COLUMN]].assign(ml_pred=oof)
    flows = flows.merge(data_oof, on=config.FEATURES + [config.LABEL_COLUMN], how="left", validate="many_to_one")
    assert flows["ml_pred"].notna().all(), "every flow should map to a duplicate-free record"
    flows["ml_pred"] = flows["ml_pred"].astype(int)
    ml_all = evaluate(flows[TARGET_COLUMN], flows["ml_pred"])
    print(f"Scanner source also sent benign flows: "
          f"{int(((flows['Source IP'] == '172.16.0.1') & (flows[TARGET_COLUMN] == 0)).sum()):,}")
    rows = []
    for t in THRESHOLDS:
        rows.append({"detector": f"Threshold >= {t} targets/min", "threshold": t,
                     **evaluate(flows[TARGET_COLUMN], threshold_detect(flows, t))})
    rows.append({"detector": f"{best} (out-of-fold)", "threshold": np.nan, **ml_all})
    base = pd.DataFrame(rows)
    base.to_csv(T / "threshold_vs_model.csv", index=False)
    print(base[["detector"] + METRIC_COLS + ["fp", "fn"]].round(4).to_string(index=False))
    th = base.dropna(subset=["threshold"])
    best_t = int(th.loc[th["f1"].idxmax(), "threshold"])
    print(f"Best threshold by F1: {best_t}")
    plot_threshold_sweep(th, ml_all, best)

    # ------------------------------------------------------------ 8. slow scans
    header(f"8. Slow scan simulation (threshold fixed at {best_t})")
    rng = np.random.default_rng(config.RANDOM_STATE)
    is_scan = flows[TARGET_COLUMN].values == 1
    slow_rows = []
    for k in SLOWDOWN:
        keep = ~is_scan | (rng.random(len(flows)) < 1 / k)
        sub = flows[keep]
        th_m = evaluate(sub[TARGET_COLUMN], threshold_detect(sub, best_t))
        ml_m = evaluate(sub[TARGET_COLUMN], sub["ml_pred"])
        slow_rows.append({"slowdown_factor": k, "scan_flows_kept": int(sub[TARGET_COLUMN].sum()),
                          "threshold_recall": th_m["recall"], "threshold_f1": th_m["f1"],
                          "model_recall": ml_m["recall"], "model_f1": ml_m["f1"]})
    slow = pd.DataFrame(slow_rows)
    slow.to_csv(T / "slow_scan_simulation.csv", index=False)
    print(slow.round(4).to_string(index=False))
    plot_slow_scan(slow, best, best_t)

    # ------------------------------------------------------------ save the best model
    save_model(best_model, best, results[best], extra={
        "train_records": int(len(X_train)), "test_records": int(len(X_test)),
        "test_scans": int(y_test.sum()),
        "cv_f1_mean": float(cv_summary.loc[best, ("f1", "mean")]),
        "cv_f1_std": float(cv_summary.loc[best, ("f1", "std")]),
    })
    print(f"\nSaved {best} to {config.MODEL_PATH.relative_to(config.PROJECT_ROOT).as_posix()}")


# ---------------------------------------------------------------- figures
def plot_confusion_matrices(results):
    fig, axes = plt.subplots(1, len(results), figsize=(10, 3.4))
    for ax, (name, m) in zip(axes, results.items()):
        cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        ax.imshow(np.log10(cm + 1), cmap="Blues", vmin=0, vmax=np.log10(cm.max() + 1) * 1.15)
        for (i, j), v in np.ndenumerate(cm):
            dark = np.log10(v + 1) > np.log10(cm.max() + 1) * 0.6
            ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=12,
                    color="white" if dark else TEXT_PRIMARY)
        ax.set_xticks([0, 1], ["Benign", "Port scan"])
        ax.set_yticks([0, 1], ["Benign", "Port scan"])
        ax.set_xlabel("Predicted")
        ax.set_title(name)
        ax.grid(False)
        for s in ax.spines.values():
            s.set_visible(False)
    axes[0].set_ylabel("Actual")
    fig.tight_layout()
    save(fig, F / "fig_confusion_matrices.png")


def plot_feature_importance(imp):
    d = imp.sort_values("permutation_f1_drop_mean")
    fig, ax = plt.subplots(figsize=(6.5, 5.2))
    ax.barh(d["feature"], d["permutation_f1_drop_mean"], xerr=d["permutation_f1_drop_std"],
            color=PORTSCAN_COLOR, height=0.65, error_kw={"ecolor": TEXT_SECONDARY, "lw": 1})
    ax.set_xlabel("Drop in F1-score when the feature is shuffled")
    ax.grid(axis="y", visible=False)
    save(fig, F / "fig_feature_importance.png")


def plot_threshold_sweep(th, ml, best):
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    ax.plot(th["threshold"], th["recall"], marker="o", ms=5, lw=2, color=PORTSCAN_COLOR, label="Threshold: recall")
    ax.plot(th["threshold"], th["precision"], marker="s", ms=5, lw=2, color=BENIGN_COLOR, label="Threshold: precision")
    ax.axhline(ml["f1"], color=TEXT_PRIMARY, lw=1.5, ls="--", label=f"{best}: F1 = {ml['f1']:.4f}")
    ax.set_xscale("log")
    ax.set_xticks(THRESHOLDS, [str(t) for t in THRESHOLDS])
    ax.minorticks_off()
    ax.set_xlabel("Threshold (distinct targets per source per minute)")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower left")
    save(fig, F / "fig_threshold_vs_model.png")


def plot_slow_scan(slow, best, best_t):
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    ax.plot(slow["slowdown_factor"], slow["model_recall"], marker="o", ms=6, lw=2, color=BENIGN_COLOR, label=best)
    ax.plot(slow["slowdown_factor"], slow["threshold_recall"], marker="s", ms=6, lw=2, color=PORTSCAN_COLOR,
            label=f"Threshold (>= {best_t} targets/min)")
    ax.set_xscale("log")
    ax.set_xticks(SLOWDOWN, [f"{k}x" for k in SLOWDOWN])
    ax.minorticks_off()
    ax.set_xlabel("Scan slowed down by (fraction of scan flows kept = 1 / factor)")
    ax.set_ylabel("Recall (share of scan flows detected)")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower left")
    save(fig, F / "fig_slow_scan.png")


if __name__ == "__main__":
    main()
