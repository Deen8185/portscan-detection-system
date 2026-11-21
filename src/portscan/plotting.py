"""Shared chart style for report figures (printed, light background)."""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Validated categorical slots 1 and 2 (colour-blind safe as a pair).
BENIGN_COLOR = "#2a78d6"
PORTSCAN_COLOR = "#eb6834"
CLASS_COLORS = {"BENIGN": BENIGN_COLOR, "PortScan": PORTSCAN_COLOR}
CLASS_DISPLAY = {"BENIGN": "Benign", "PortScan": "Port scan"}
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"


def apply_style() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif"],
        "font.size": 11,
        "axes.edgecolor": TEXT_SECONDARY,
        "axes.labelcolor": TEXT_PRIMARY,
        "axes.titlesize": 12,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "xtick.color": TEXT_SECONDARY,
        "ytick.color": TEXT_SECONDARY,
        "legend.frameon": False,
        "figure.dpi": 100,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
    })


def save(fig, path) -> None:
    fig.savefig(path, facecolor="white")
    plt.close(fig)
