"""Phase 6: how long an analysis takes as the uploaded file grows.

Run from the project folder (after scripts/train_models.py):
    python scripts/performance_test.py

Files of 1,000 to 286,467 original CICIDS2017 rows are written as CSV text
and analysed exactly as the dashboard does: read the CSV, classify every
flow, discover services and save the summary (to a temporary database).
Each size is run three times and the median is reported.

Outputs: reports/tables/performance_test.csv, reports/figures/fig_performance.png
"""

import io
import platform
import statistics
import tempfile
import time
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from portscan import config, database
from portscan.modeling import load_model
from portscan.pipeline import analyse_flows
from portscan.plotting import BENIGN_COLOR, PORTSCAN_COLOR, TEXT_PRIMARY, apply_style, save

SIZES = [1_000, 5_000, 10_000, 50_000, 100_000, None]   # None = the whole capture
REPEATS = 3


def main():
    model, meta = load_model()
    raw = pd.read_csv(config.RAW_DATASET_PATH, encoding="latin1", low_memory=False)
    print(f"Machine: {platform.processor() or platform.machine()} | Python {platform.python_version()}")
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "perf.db"
        for size in SIZES:
            part = raw if size is None else raw.sample(size, random_state=config.RANDOM_STATE)
            text = part.to_csv(index=False)
            mb = len(text.encode()) / 1e6
            times = {"read": [], "analyse_and_save": [], "total": []}
            for _ in range(REPEATS):
                t0 = time.perf_counter()
                df = pd.read_csv(io.StringIO(text), low_memory=False)
                t1 = time.perf_counter()
                with database.open_db(db_path) as conn:
                    result = analyse_flows(df, model=model, model_name=meta["model_name"],
                                           file_name=f"perf_{len(part)}.csv", conn=conn)
                t2 = time.perf_counter()
                times["read"].append(t1 - t0)
                times["analyse_and_save"].append(t2 - t1)
                times["total"].append(t2 - t0)
            med = {k: statistics.median(v) for k, v in times.items()}
            rows.append({"flows": len(part), "file_size_mb": round(mb, 1),
                         "read_seconds": round(med["read"], 2),
                         "analyse_and_save_seconds": round(med["analyse_and_save"], 2),
                         "total_seconds": round(med["total"], 2),
                         "flows_per_second": int(len(part) / med["total"]),
                         "scan_flows": result.scan_flows, "targeted_ports": len(result.discovery.services)})
            print(rows[-1], flush=True)

    perf = pd.DataFrame(rows)
    perf.to_csv(config.TABLES_DIR / "performance_test.csv", index=False)
    print("\n" + perf.to_string(index=False))

    apply_style()
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    ax.plot(perf["flows"], perf["total_seconds"], marker="o", ms=6, lw=2, color=PORTSCAN_COLOR,
            label="Total (read file + analyse + save)")
    ax.plot(perf["flows"], perf["analyse_and_save_seconds"], marker="s", ms=6, lw=2, color=BENIGN_COLOR,
            label="Analyse + save only")
    # Linear axis: time grows roughly in proportion to the number of flows.
    for x, y in zip(perf["flows"], perf["total_seconds"]):
        if x >= 50_000:
            ax.annotate(f"{y:.1f} s", (x, y), textcoords="offset points", xytext=(0, 8), ha="center",
                        fontsize=9, color=TEXT_PRIMARY)
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_xlim(0, perf["flows"].max() * 1.05)
    ax.set_xlabel("Flows in the uploaded file")
    ax.set_ylabel("Time (seconds)")
    ax.set_ylim(0, perf["total_seconds"].max() * 1.2)
    ax.legend(loc="upper left")
    save(fig, config.FIGURES_DIR / "fig_performance.png")


if __name__ == "__main__":
    main()
