"""Phase 7: train and evaluate the lab model on recorded lab scenarios.

Run from the project folder (after lab/record_all.sh has recorded the
scenarios into lab/captures):
    python scripts/train_lab_model.py

Flows are labelled from the recording metadata: every flow to or from the
scanner's address is part of the scan, everything else is normal traffic.
The model is trained only on the train_* scenarios and evaluated on each
held-out test_* scenario, which include scan types and a real slow scan
that the model never saw.

Compared on the same test flows:
  * the lab model (Random Forest, same settings as the CICIDS2017 model);
  * a threshold detector whose threshold is chosen on the training scenarios;
  * the CICIDS2017 model, to measure how well a model trained on one flow
    exporter transfers to another.
Service discovery is checked against the open ports Nmap itself reported.
"""

import json
import xml.etree.ElementTree as ET

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone

from portscan import config
from portscan.baseline import threshold_detect
from portscan.formats import PYTHON_CICFLOWMETER, to_canonical
from portscan.modeling import (CICIDS2017_FORMAT, build_models, cross_validate, evaluate,
                               load_model, model_available, save_model)
from portscan.plotting import (BENIGN_COLOR, PORTSCAN_COLOR, TEXT_PRIMARY, apply_style, save)
from portscan.preprocessing import TARGET_COLUMN, to_numeric_features
from portscan.service_discovery import discover_services

CAP, T, F = config.LAB_CAPTURES_DIR, config.TABLES_DIR, config.FIGURES_DIR
THRESHOLDS = [2, 3, 5, 10, 15, 20, 30, 50, 100, 200, 500]
SCENARIO_TEXT = {
    "test_normal": "Normal use only",
    "test_version": "Service/version scan (-sV)",
    "test_udp": "UDP scan (-sU)",
    "test_fin": "FIN scan (-sF)",
    "test_fullrange": "All 65,535 ports (-p-)",
    "test_slow": "Real slow scan (15 s between probes)",
}


def load_scenario(name: str) -> tuple[pd.DataFrame, dict]:
    meta = json.loads((CAP / f"{name}.json").read_text())
    path = CAP / f"{name}.csv"
    if not path.exists():
        path = CAP / f"{name}.csv.gz"          # large captures are stored compressed
    df, fmt = to_canonical(pd.read_csv(path, low_memory=False))
    assert fmt == PYTHON_CICFLOWMETER, f"{name}: unexpected format {fmt}"
    scanner = meta["scanner_ip"]
    df[TARGET_COLUMN] = ((df["Source IP"] == scanner) | (df["Destination IP"] == scanner)).astype(int)
    X = to_numeric_features(df)
    ok = X.notna().all(axis=1) & (X[["Flow Duration", "Flow IAT Mean"]] >= 0).all(axis=1)
    df = df.loc[ok].assign(**{c: X.loc[ok, c] for c in config.FEATURES})
    df["scenario"] = name
    return df.reset_index(drop=True), meta


def open_ports_from_nmap(name: str) -> dict[int, str]:
    path = CAP / f"{name}.nmap.xml"
    if not path.exists():
        return {}
    ports = {}
    for p in ET.parse(path).getroot().iter("port"):
        state = p.find("state")
        if state is not None and state.get("state") == "open":
            svc = p.find("service")
            ports[int(p.get("portid"))] = svc.get("name") if svc is not None else "?"
    return ports


def main():
    names = sorted(p.stem for p in CAP.glob("*.json"))
    train_names = [n for n in names if n.startswith("train_")]
    test_names = [n for n in names if n.startswith("test_")]
    data = {n: load_scenario(n) for n in train_names + test_names}

    summary = pd.DataFrame([{"scenario": n, "set": "train" if n in train_names else "test",
                             "nmap": m["nmap_args"] or "(none)", "flows": len(d),
                             "scan_flows": int(d[TARGET_COLUMN].sum()),
                             "normal_flows": int((d[TARGET_COLUMN] == 0).sum())}
                            for n, (d, m) in data.items()])
    summary.to_csv(T / "lab_scenarios.csv", index=False)
    print("Recorded scenarios\n" + summary.to_string(index=False))

    # ------------------------------------------------------------ train
    train = pd.concat([data[n][0] for n in train_names], ignore_index=True)
    conflicts = int((train.groupby(config.FEATURES)[TARGET_COLUMN].nunique() > 1).sum())
    train_u = train.drop_duplicates(subset=config.FEATURES + [TARGET_COLUMN])
    print(f"\nTraining records: {len(train):,} flows -> {len(train_u):,} after removing duplicates "
          f"({int(train_u[TARGET_COLUMN].sum()):,} scan); records with conflicting labels: {conflicts}")
    rf = build_models()["Random Forest"]
    X_tr, y_tr = train_u[config.FEATURES], train_u[TARGET_COLUMN]
    cv = cross_validate(rf, X_tr, y_tr)
    print(f"5-fold CV on training scenarios: F1 {cv.f1.mean():.4f} ± {cv.f1.std():.4f}")
    model = clone(rf).fit(X_tr, y_tr)

    # threshold chosen on the training scenarios only
    best_t, best_f1 = None, -1
    for t in THRESHOLDS:
        f1 = evaluate(train[TARGET_COLUMN], threshold_detect(train, t))["f1"]
        if f1 > best_f1:
            best_t, best_f1 = t, f1
    print(f"Threshold chosen on training scenarios: >= {best_t} targets/min (F1 {best_f1:.4f})")

    cicids = load_model(CICIDS2017_FORMAT)[0] if model_available(CICIDS2017_FORMAT) else None

    # ------------------------------------------------------------ evaluate
    rows, all_test = [], []
    for n in test_names:
        d, meta = data[n]
        y = d[TARGET_COLUMN]
        pred = model.predict(d[config.FEATURES])
        lab = evaluate(y, pred)
        thr = evaluate(y, threshold_detect(d, best_t))
        cic = evaluate(y, cicids.predict(d[config.FEATURES])) if cicids is not None else {}
        found = set(discover_services(d, pred).services["port"]) if pred.sum() else set()
        open_ports = open_ports_from_nmap(n)
        rows.append({
            "scenario": n, "description": SCENARIO_TEXT.get(n, n), "flows": len(d),
            "scan_flows": int(y.sum()), "normal_flows": int((y == 0).sum()),
            "lab_recall": lab["recall"], "lab_precision": lab["precision"], "lab_f1": lab["f1"],
            "lab_false_alarms": lab["fp"], "lab_fpr": lab["fpr"],
            "threshold_recall": thr["recall"], "threshold_false_alarms": thr["fp"],
            "cicids2017_model_recall": cic.get("recall", np.nan),
            "nmap_open_ports": ", ".join(f"{p}/{s}" for p, s in sorted(open_ports.items())),
            "open_ports_reported": f"{len(found & set(open_ports))}/{len(open_ports)}" if open_ports else "-",
        })
        all_test.append(d.assign(pred=pred))
    res = pd.DataFrame(rows)
    res.to_csv(T / "lab_test_results.csv", index=False)
    print("\nHeld-out test scenarios")
    print(res.drop(columns=["description", "nmap_open_ports"]).round(4).to_string(index=False))

    test_all = pd.concat(all_test, ignore_index=True)
    overall = evaluate(test_all[TARGET_COLUMN], test_all["pred"])
    print(f"\nAll test flows: recall {overall['recall']:.4f}, precision {overall['precision']:.4f}, "
          f"F1 {overall['f1']:.4f}, false alarms {overall['fp']} of {overall['tn'] + overall['fp']:,} normal flows")

    scan_rows = res[res["scan_flows"] > 0]
    macro = {"lab": scan_rows["lab_recall"].mean(), "threshold": scan_rows["threshold_recall"].mean(),
             "cicids2017": scan_rows["cicids2017_model_recall"].mean()}
    print("Average recall over the scan scenarios (each scenario counts equally): "
          + ", ".join(f"{k} {v:.4f}" for k, v in macro.items()))

    imp = pd.DataFrame({"feature": config.FEATURES, "importance": model.feature_importances_})
    imp.sort_values("importance", ascending=False).to_csv(T / "lab_feature_importance.csv", index=False)

    save_model(model, "Random Forest", overall, flow_format=PYTHON_CICFLOWMETER, extra={
        "dataset": "Lab captures (Python CICFlowMeter 0.5)",
        "train_scenarios": train_names, "test_scenarios": test_names,
        "train_records": int(len(train_u)), "test_records": int(len(test_all)),
        "test_scans": int(test_all[TARGET_COLUMN].sum()),
        "cv_f1_mean": float(cv.f1.mean()), "cv_f1_std": float(cv.f1.std()),
        "threshold_targets_per_min": best_t,
        "macro_recall_scan_scenarios": float(macro["lab"]),
        "macro_recall_threshold": float(macro["threshold"]),
        "false_alarms_total": int(overall["fp"]),
        "normal_flows_total": int(overall["tn"] + overall["fp"]),
    })
    print(f"\nSaved the lab model to {config.LAB_MODEL_PATH.relative_to(config.PROJECT_ROOT).as_posix()}")

    apply_style()
    plot_recall(res, best_t)
    export_samples(test_names)


def export_samples(test_names):
    """Copy held-out test captures (original Python CICFlowMeter columns) to
    data/samples so the dashboard can demonstrate the lab model."""
    wanted = {"test_version": "lab_version_scan.csv", "test_slow": "lab_slow_scan.csv",
              "test_normal": "lab_normal_only.csv", "test_fin": "lab_fin_scan.csv"}
    for name, out in wanted.items():
        src = CAP / f"{name}.csv"
        if name in test_names and src.exists() and src.stat().st_size < 8_000_000:
            (config.SAMPLES_DIR / out).write_bytes(src.read_bytes())
            print(f"Sample written: data/samples/{out}")


def plot_recall(res, best_t):
    d = res[res["scan_flows"] > 0]
    x = np.arange(len(d))
    w = 0.27
    fig, ax = plt.subplots(figsize=(7.5, 4.4))
    series = [("lab_recall", "Lab model", BENIGN_COLOR),
              ("threshold_recall", f"Threshold (>= {best_t} targets/min)", PORTSCAN_COLOR),
              ("cicids2017_model_recall", "CICIDS2017 model", "#8a8984")]
    for i, (col, label, color) in enumerate(series):
        bars = ax.bar(x + (i - 1) * (w + 0.01), d[col].fillna(0), w, color=color, label=label)
        ax.bar_label(bars, labels=[f"{v:.2f}" for v in d[col].fillna(0)], padding=2, fontsize=8,
                     color=TEXT_PRIMARY)
    ax.set_xticks(x, [s.replace(" (", "\n(") for s in d["description"]], fontsize=9)
    ax.set_ylabel("Recall (share of scan flows detected)")
    ax.set_ylim(0, 1.15)
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper center", ncols=3, bbox_to_anchor=(0.5, 1.12), fontsize=9)
    save(fig, F / "fig_lab_scenarios.png")


if __name__ == "__main__":
    main()
