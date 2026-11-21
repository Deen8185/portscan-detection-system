"""Phase 3: run detection plus service discovery on the whole capture.

Run from the project folder (after scripts/train_models.py):
    python scripts/discover_services.py

The saved model classifies every cleaned flow of the CICIDS2017 port scan
capture, then the service discovery module lists the targeted services.
Because the true labels are known, the discovered ports are compared with
the ports the scanner really probed.

Note: this is a demonstration of the whole pipeline on the full capture,
not a model evaluation. Most of these flows share feature records with the
model's training data; the unbiased scores are in reports/tables
(model_comparison.csv, cross_validation_summary.csv, threshold_vs_model.csv).
"""

import json

import matplotlib.pyplot as plt
import pandas as pd

from portscan import config
from portscan.modeling import load_model
from portscan.plotting import TEXT_PRIMARY, apply_style, save
from portscan.preprocessing import TARGET_COLUMN, prepare_for_inference
from portscan.service_discovery import discover_services, targeted_hosts

RISK_COLORS = {"High": "#e34948", "Medium": "#eda100", "Low": "#2a78d6", "Unknown": "#8a8984"}


def main():
    T, F = config.TABLES_DIR, config.FIGURES_DIR
    model, meta = load_model()
    flows = pd.read_csv(config.PROCESSED_DIR / "flows_clean.csv")
    X, valid = prepare_for_inference(flows)
    flows = flows[valid]
    pred = model.predict(X)
    print(f"Model: {meta['model_name']} | flows classified: {len(flows):,} | predicted scans: {int(pred.sum()):,}")

    result = discover_services(flows, pred)
    services = result.services
    services.to_csv(T / "discovered_services.csv", index=False)
    result.risk_summary().to_csv(T / "discovered_services_by_risk.csv", index=False)
    result.range_summary().to_csv(T / "discovered_services_by_port_range.csv", index=False)
    targeted_hosts(flows, pred).to_csv(T / "targeted_hosts.csv", index=False)

    actual = set(flows.loc[flows[TARGET_COLUMN] == 1, config.DESTINATION_PORT_COLUMN].astype(int))
    found = set(services["port"])
    check = {
        "ports_really_scanned": len(actual),
        "ports_discovered": len(found),
        "correctly_discovered": len(actual & found),
        "missed": len(actual - found),
        "reported_but_not_scanned": len(found - actual),
        "port_coverage_pct": round(100 * len(actual & found) / len(actual), 2),
        "reported_but_not_scanned_ports": sorted(found - actual),
    }
    (T / "service_discovery_check.json").write_text(json.dumps(check, indent=2))

    print("\nTop 15 targeted services")
    print(services.head(15)[["port", "service", "risk_level", "hit_count", "share_pct"]].to_string(index=False))
    print("\nBy risk level")
    print(result.risk_summary().to_string(index=False))
    print("\nBy port range")
    print(result.range_summary().to_string(index=False))
    print("\nTargeted hosts")
    print(targeted_hosts(flows, pred).head().to_string(index=False))
    print("\nDiscovered ports compared with the ports really scanned")
    print(json.dumps(check, indent=2))

    apply_style()
    plot_top_services(services.head(15), F / "fig_discovered_services.png")


def plot_top_services(top, path):
    labels = [f"{r.port} {r.service}" if r.service != "Unknown service" else f"{r.port} (unknown)"
              for r in top.itertuples()]
    colors = [RISK_COLORS[r] for r in top["risk_level"]]
    fig, ax = plt.subplots(figsize=(6.8, 5.2))
    bars = ax.barh(labels[::-1], top["hit_count"].values[::-1], color=colors[::-1], height=0.65)
    ax.bar_label(bars, labels=[f"{v:,}" for v in top["hit_count"].values[::-1]],
                 padding=3, color=TEXT_PRIMARY, fontsize=10)
    ax.set_xlabel("Scan flows aimed at the port")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, top["hit_count"].max() * 1.15)
    present = [r for r in RISK_COLORS if r in set(top["risk_level"])]
    handles = [plt.Rectangle((0, 0), 1, 1, color=RISK_COLORS[r]) for r in present]
    ax.legend(handles, [f"{r} risk" if r != "Unknown" else "Unknown" for r in present],
              loc="lower right", title=None)
    save(fig, path)


if __name__ == "__main__":
    main()
