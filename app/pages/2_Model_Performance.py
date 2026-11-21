"""How the detection model was chosen and how well it performs."""

import json

import pandas as pd
import streamlit as st

import ui
from portscan import config

ui.page_setup("Model Performance")
ui.require_model()
_, meta = ui.get_model()
T, F = config.TABLES_DIR, config.FIGURES_DIR

m = meta["test_metrics"]
st.markdown(
    f"The system uses a **{meta['model_name']}** trained on {meta['train_records']:,} "
    f"duplicate-free flow records from the CICIDS2017 port scan capture and tested on "
    f"{meta['test_records']:,} records it had never seen ({meta['test_scans']} of them port scans). "
    f"It was chosen because it had the highest mean F1-score in 5-fold cross-validation "
    f"({meta['cv_f1_mean']:.4f} ± {meta['cv_f1_std']:.4f}).")

c = st.columns(5)
c[0].metric("Accuracy", f"{m['accuracy']:.4f}")
c[1].metric("Precision", f"{m['precision']:.4f}")
c[2].metric("Recall (detection rate)", f"{m['recall']:.4f}")
c[3].metric("F1-score", f"{m['f1']:.4f}")
c[4].metric("False positive rate", f"{m['fpr']:.5f}")
st.caption(f"On the test set: {int(m['tp'])} scans detected, {int(m['fn'])} missed, "
           f"{int(m['fp'])} false alarm(s) among {int(m['tn'] + m['fp']):,} benign flows.")


LABELS = {"model": "Model", "detector": "Detector", "features": "Features", "accuracy": "Accuracy",
          "precision": "Precision", "recall": "Recall", "f1": "F1-score", "fpr": "False positive rate",
          "fp": "False alarms", "fn": "Missed scans", "train_seconds": "Training time (s)",
          "predict_ms_per_1000_flows": "Prediction time per 1,000 flows (ms)",
          "slowdown_factor": "Slowed down by", "scan_flows_kept": "Scan flows kept",
          "threshold_recall": "Threshold recall", "threshold_f1": "Threshold F1",
          "model_recall": "Model recall", "model_f1": "Model F1", "step": "Step",
          "rows_removed": "Rows removed", "rows_remaining": "Rows remaining",
          "benign": "Benign", "portscan": "Port scan"}


def table(name):
    path = T / name
    return pd.read_csv(path) if path.exists() else None


def show(df, **kw):
    st.dataframe(df.rename(columns=LABELS), hide_index=True, width="stretch", **kw)


def figure(name, caption):
    path = F / name
    if path.exists():
        st.image(str(path), caption=caption)


tabs = st.tabs(["Model comparison", "Threshold detection vs ML", "Slow scans",
                "Features", "Data cleaning"])

with tabs[0]:
    comp = table("model_comparison.csv")
    cv = table("cross_validation_folds.csv")
    if comp is not None:
        st.markdown("**Test-set results (80:20 split)**")
        show(comp[["model", "accuracy", "precision", "recall", "f1", "fpr", "fp", "fn",
                   "train_seconds", "predict_ms_per_1000_flows"]].round(4))
    if cv is not None:
        st.markdown("**5-fold cross-validation (mean ± standard deviation)**")
        s = cv.groupby("model")[["precision", "recall", "f1", "fpr"]].agg(["mean", "std"])
        s = pd.DataFrame({LABELS[m]: s[(m, "mean")].map("{:.4f}".format) + " ± " + s[(m, "std")].map("{:.4f}".format)
                          for m in ("precision", "recall", "f1", "fpr")}).reset_index()
        show(s)
    figure("fig_confusion_matrices.png", "Confusion matrices on the test set")
    dup = table("with_duplicates_comparison.csv")
    if dup is not None:
        st.markdown("**Why duplicates were removed**")
        st.write(f"If duplicate records are kept, {dup['test_scans_identical_to_a_training_row_pct'].iloc[0]}% of the "
                 "scan flows in the test set are exact copies of training records, and every model scores "
                 "about 0.9999. Removing duplicates gives an honest estimate.")
        show(dup[["model", "precision", "recall", "f1", "fpr"]].round(4))

with tabs[1]:
    th = table("threshold_vs_model.csv")
    if th is not None:
        st.write("A threshold detector flags a source that contacts at least N distinct "
                 "host-and-port targets in one minute, as rule-based intrusion detection systems do. "
                 "Low thresholds flag much benign traffic; the model avoids this without any tuning.")
        show(th[["detector", "precision", "recall", "f1", "fpr", "fp", "fn"]].round(4))
    figure("fig_threshold_vs_model.png", "Threshold detection compared with the model on all 286,060 flows")

with tabs[2]:
    slow = table("slow_scan_simulation.csv")
    if slow is not None:
        st.write("Scan traffic was thinned out to imitate a scanner running 10 to 1,000 times slower. "
                 "The threshold detector stops detecting the scan, while the model, which judges each "
                 "flow on its own behaviour, keeps detecting it.")
        show(slow.assign(slowdown_factor=slow["slowdown_factor"].map("{}x".format)).round(4))
    figure("fig_slow_scan.png", "Detection rate as the scan is slowed down (simulation)")

with tabs[3]:
    figure("fig_feature_importance.png", "Permutation importance: drop in F1-score when a feature is shuffled")
    abl = table("ablation_init_win.csv")
    if abl is not None:
        st.markdown("**Without the TCP window-size features**")
        show(abl.rename(columns={abl.columns[0]: "features"})[["features", "precision", "recall", "f1", "fpr"]].round(4))
    st.markdown("**Features used by the model** (Table 3.1)")
    st.write(", ".join(meta["features"]))

with tabs[4]:
    steps = table("cleaning_steps.csv")
    if steps is not None:
        show(steps)
    figure("fig_class_distribution.png", "Flows per class before and after cleaning")
    facts = T / "dataset_facts.json"
    if facts.exists():
        f = json.loads(facts.read_text())
        st.caption(f"Capture: {f['capture_start']} to {f['capture_end']}. "
                   f"{f['distinct_ports_scanned']:,} distinct ports were scanned.")
