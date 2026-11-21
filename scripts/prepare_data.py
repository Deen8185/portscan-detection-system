"""Phase 1: clean the CICIDS2017 port scan data and describe it.

Run from the project folder:
    python scripts/prepare_data.py

Outputs
    data/processed/flows_clean.csv     every valid flow, timestamps corrected
                                       (used by the threshold-based baseline)
    data/processed/model_dataset.csv   duplicate-free records for training
    reports/tables/*.csv, *.json       numbers for Chapter Four
    reports/figures/*.png              charts for Chapter Four
"""

import json

import numpy as np
import pandas as pd

from portscan import config
from portscan.plotting import (CLASS_COLORS, CLASS_DISPLAY, PORTSCAN_COLOR,
                               TEXT_PRIMARY, apply_style, save)
from portscan.preprocessing import (TARGET_COLUMN, clean_dataset,
                                    conflicting_label_count, fix_timestamps,
                                    load_raw_dataset)
import matplotlib.pyplot as plt

ID_COLUMNS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]


def main() -> None:
    for d in (config.PROCESSED_DIR, config.TABLES_DIR, config.FIGURES_DIR):
        d.mkdir(parents=True, exist_ok=True)

    print(f"Loading {config.RAW_DATASET_PATH.name} ...")
    raw = load_raw_dataset()

    # ---- full clean data (no de-duplication) for the threshold baseline
    flows, _ = clean_dataset(raw, deduplicate=False)
    flows["Timestamp"] = fix_timestamps(flows["Timestamp"])
    keep = ["Timestamp", "Source IP", "Source Port", "Destination IP",
            config.DESTINATION_PORT_COLUMN, "Protocol"] + config.FEATURES + [config.LABEL_COLUMN, TARGET_COLUMN]
    flows[keep].to_csv(config.PROCESSED_DIR / "flows_clean.csv", index=False)

    # ---- duplicate-free model dataset
    model_df, report = clean_dataset(raw, deduplicate=True)
    model_cols = config.FEATURES + [config.DESTINATION_PORT_COLUMN, config.LABEL_COLUMN, TARGET_COLUMN]
    model_df[model_cols].to_csv(config.PROCESSED_DIR / "model_dataset.csv", index=False)

    steps = report.to_frame()
    steps.to_csv(config.TABLES_DIR / "cleaning_steps.csv", index=False)
    print("\nCleaning steps")
    print(steps.to_string(index=False))

    # ---- facts about the data, for the report
    scans = flows[flows[config.LABEL_COLUMN] == config.PORTSCAN_LABEL]
    all_feature_cols = [c for c in raw.columns if c not in ID_COLUMNS + [config.LABEL_COLUMN]]
    facts = {
        "raw_rows": int(len(raw)),
        "raw_columns": int(raw.shape[1]),
        "valid_rows_before_dedup": int(len(flows)),
        "model_rows": int(len(model_df)),
        "model_benign": int((model_df[TARGET_COLUMN] == 0).sum()),
        "model_portscan": int((model_df[TARGET_COLUMN] == 1).sum()),
        "portscan_share_after_dedup_pct": round(100 * model_df[TARGET_COLUMN].mean(), 2),
        "feature_records_with_conflicting_labels": conflicting_label_count(flows),
        "duplicates_using_all_cicflowmeter_features": int(raw.duplicated(subset=all_feature_cols + [config.LABEL_COLUMN]).sum()),
        "capture_start": str(flows["Timestamp"].min()),
        "capture_end": str(flows["Timestamp"].max()),
        "scan_source_ips": scans["Source IP"].value_counts().to_dict(),
        "scan_destination_ips": scans["Destination IP"].value_counts().to_dict(),
        "distinct_ports_scanned": int(scans[config.DESTINATION_PORT_COLUMN].nunique()),
        "scan_flows_by_protocol": {str(k): int(v) for k, v in scans["Protocol"].value_counts().items()},
    }
    (config.TABLES_DIR / "dataset_facts.json").write_text(json.dumps(facts, indent=2))
    print("\nDataset facts")
    print(json.dumps(facts, indent=2))

    # ---- feature medians by class (on the duplicate-free data)
    medians = model_df.groupby(config.LABEL_COLUMN)[config.FEATURES].median().T
    medians.to_csv(config.TABLES_DIR / "feature_medians_by_class.csv")

    # ---- most scanned ports (all scan flows: every probe counts)
    top_ports = scans[config.DESTINATION_PORT_COLUMN].value_counts().head(15)
    top_ports.rename_axis("port").rename("scan_flows").to_csv(config.TABLES_DIR / "top_scanned_ports.csv")

    apply_style()
    plot_class_distribution(steps)
    plot_feature_distributions(model_df)
    plot_top_ports(top_ports)
    print("\nSaved data to data/processed, tables to reports/tables, figures to reports/figures")


def plot_class_distribution(steps: pd.DataFrame) -> None:
    """Flows per class before cleaning and after removing duplicates."""
    first, last = steps.iloc[0], steps.iloc[-1]
    stages = ["Raw dataset", "After cleaning and\nde-duplication"]
    benign = [first.benign, last.benign]
    scan = [first.portscan, last.portscan]
    x = np.arange(len(stages))
    w = 0.36
    fig, ax = plt.subplots(figsize=(6.5, 4))
    for offset, values, label in ((-w / 2 - 0.01, benign, "BENIGN"), (w / 2 + 0.01, scan, "PortScan")):
        bars = ax.bar(x + offset, values, w, color=CLASS_COLORS[label], label=CLASS_DISPLAY[label])
        ax.bar_label(bars, labels=[f"{v:,}" for v in values], padding=3, color=TEXT_PRIMARY, fontsize=10)
    ax.set_xticks(x, stages)
    ax.set_ylabel("Number of flows")
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.grid(axis="x", visible=False)
    ax.set_ylim(0, max(benign + scan) * 1.15)
    ax.legend(loc="upper right")
    save(fig, config.FIGURES_DIR / "fig_class_distribution.png")


def plot_feature_distributions(model_df: pd.DataFrame) -> None:
    """Box plots of six behavioural features by class (log scale)."""
    features = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                "Total Length of Fwd Packets", "Average Packet Size", "Init_Win_bytes_forward"]
    fig, axes = plt.subplots(2, 3, figsize=(9, 5.5))
    for ax, feat in zip(axes.flat, features):
        data = [model_df.loc[model_df[config.LABEL_COLUMN] == lbl, feat].clip(lower=0) + 1
                for lbl in ("BENIGN", "PortScan")]
        bp = ax.boxplot(data, tick_labels=["Benign", "Port scan"], showfliers=False,
                        patch_artist=True, widths=0.55, medianprops={"color": TEXT_PRIMARY, "linewidth": 1.5})
        for patch, lbl in zip(bp["boxes"], ("BENIGN", "PortScan")):
            patch.set_facecolor(CLASS_COLORS[lbl])
            patch.set_alpha(0.85)
            patch.set_edgecolor("white")
        ax.set_yscale("log")
        ax.set_title(feat, fontsize=11)
        ax.grid(axis="x", visible=False)
    fig.supylabel("Value + 1 (log scale)")
    fig.tight_layout()
    save(fig, config.FIGURES_DIR / "fig_feature_distributions.png")


def plot_top_ports(top_ports: pd.Series) -> None:
    """The 15 destination ports that received the most scan flows."""
    labels = [f"Port {p}" for p in top_ports.index]
    fig, ax = plt.subplots(figsize=(6.5, 5))
    bars = ax.barh(labels[::-1], top_ports.values[::-1], color=PORTSCAN_COLOR, height=0.65)
    ax.bar_label(bars, labels=[f"{v:,}" for v in top_ports.values[::-1]], padding=3, color=TEXT_PRIMARY, fontsize=10)
    ax.set_xlabel("Number of scan flows")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, top_ports.max() * 1.15)
    save(fig, config.FIGURES_DIR / "fig_top_scanned_ports.png")


if __name__ == "__main__":
    main()
