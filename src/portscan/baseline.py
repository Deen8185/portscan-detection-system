"""A threshold-based port scan detector, representing the existing approach.

It works like the scan detection in rule-based intrusion detection systems
(Section 3.2.2): for each source address, count the distinct destination
host-and-port pairs it contacts within a fixed time window, and report the
source as a scanner when the count reaches a threshold. Every flow sent by a
flagged source in that window is then labelled as a port scan.

CICIDS2017 timestamps have one-minute resolution, so the window is one minute.
"""

from __future__ import annotations

import pandas as pd

from . import config

WINDOW = "1min"


def distinct_targets_per_window(flows: pd.DataFrame, window: str = WINDOW) -> pd.Series:
    """For each flow, how many distinct (destination IP, port) pairs its source
    contacted in the same time window."""
    ts = pd.to_datetime(flows["Timestamp"])
    key = pd.DataFrame({
        "src": flows["Source IP"].values,
        "win": ts.dt.floor(window).values,
        "target": flows["Destination IP"].astype(str).values + ":" +
                  flows[config.DESTINATION_PORT_COLUMN].astype(str).values,
    }, index=flows.index)
    return key.groupby(["src", "win"])["target"].transform("nunique")


def threshold_detect(flows: pd.DataFrame, threshold: int, window: str = WINDOW) -> pd.Series:
    """1 for flows whose source reached ``threshold`` distinct targets in the window."""
    return (distinct_targets_per_window(flows, window) >= threshold).astype(int)
