"""Recognise which flow exporter produced a file and bring it to one layout.

Different versions of CICFlowMeter name their columns differently and, more
importantly, compute some features differently (units, packet lengths and
TCP flag counts). A model only works on flows from the exporter it was
trained with, so the system detects the format of every uploaded file and
uses the model trained for that format.

Supported formats
    cicids2017           The 2017 Java CICFlowMeter used for CICIDS2017
                         ("Flow Duration", "Total Fwd Packets", ...).
    python_cicflowmeter  The Python CICFlowMeter 0.5 used in the lab
                         ("flow_duration", "tot_fwd_pkts", ...).
"""

from __future__ import annotations

import pandas as pd

from . import config

CICIDS2017 = "cicids2017"
PYTHON_CICFLOWMETER = "python_cicflowmeter"

FORMAT_LABELS = {
    CICIDS2017: "CICFlowMeter 2017 (CICIDS2017 layout)",
    PYTHON_CICFLOWMETER: "Python CICFlowMeter 0.5 (lab layout)",
}

# Python CICFlowMeter column -> canonical (CICIDS2017) column
PYTHON_COLUMNS = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "pkt_size_avg": "Average Packet Size",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "dst_port": "Destination Port",
    "src_port": "Source Port",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
}


def detect_format(df: pd.DataFrame) -> str | None:
    """Return the format name, or None when the file matches no known layout."""
    cols = set(df.columns.astype(str).str.strip())
    if set(config.REQUIRED_UPLOAD_COLUMNS) <= cols:
        return CICIDS2017
    needed_python = {k for k, v in PYTHON_COLUMNS.items() if v in config.REQUIRED_UPLOAD_COLUMNS}
    if needed_python <= cols:
        return PYTHON_CICFLOWMETER
    return None


def to_canonical(df: pd.DataFrame) -> tuple[pd.DataFrame, str | None]:
    """Rename columns to the CICIDS2017 names used throughout the system.

    Values are not converted: each format keeps its own units and keeps
    being analysed by the model trained on that format.
    """
    df = df.copy()
    df.columns = df.columns.astype(str).str.strip()
    fmt = detect_format(df)
    if fmt == PYTHON_CICFLOWMETER:
        df = df.rename(columns=PYTHON_COLUMNS)
    df = df.loc[:, ~df.columns.duplicated()]
    return df, fmt
