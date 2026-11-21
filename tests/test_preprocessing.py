"""Tests for loading, cleaning and inference preparation."""

import numpy as np
import pandas as pd
import pytest

from portscan import config
from portscan.preprocessing import (TARGET_COLUMN, clean_dataset,
                                    conflicting_label_count, fix_timestamps,
                                    prepare_for_inference, strip_column_names,
                                    validate_columns)


def make_flows(n_benign=3, n_scan=3):
    """Small flow table in CICIDS2017 shape (with leading spaces in headers)."""
    rows = []
    for i in range(n_benign):
        rows.append({f: float(100 + i) for f in config.FEATURES} | {"Destination Port": 443, "Label": "BENIGN"})
    for i in range(n_scan):
        rows.append({f: float(1 + i) for f in config.FEATURES} | {"Destination Port": 22, "Label": "PortScan"})
    df = pd.DataFrame(rows)
    df.columns = [" " + c for c in df.columns]
    return df


def test_strip_column_names_removes_spaces():
    df = strip_column_names(make_flows())
    assert "Destination Port" in df.columns and "Label" in df.columns


def test_clean_encodes_labels():
    clean, _ = clean_dataset(make_flows())
    assert set(clean[TARGET_COLUMN]) == {0, 1}
    assert (clean.loc[clean["Label"] == "PortScan", TARGET_COLUMN] == 1).all()


def test_clean_removes_infinite_and_missing():
    df = make_flows()
    df.loc[0, " Flow Bytes/s"] = np.inf
    df.loc[1, " Flow Packets/s"] = np.nan
    clean, report = clean_dataset(df)
    assert len(clean) == 4
    step = report.to_frame().set_index("step").loc["Remove missing or infinite values"]
    assert step.rows_removed == 2


def test_clean_removes_negative_durations_but_keeps_minus_one_windows():
    df = make_flows()
    df.loc[0, " Flow Duration"] = -5
    df.loc[1, " Init_Win_bytes_forward"] = -1
    clean, _ = clean_dataset(df)
    assert len(clean) == 5
    assert (clean["Init_Win_bytes_forward"] == -1).any()


def test_deduplication_is_optional_and_recorded():
    df = pd.concat([make_flows(), make_flows()], ignore_index=True)
    deduped, report = clean_dataset(df, deduplicate=True)
    full, _ = clean_dataset(df, deduplicate=False)
    assert len(full) == 12 and len(deduped) == 6
    assert report.to_frame().iloc[-1].rows_removed == 6


def test_unknown_labels_are_dropped():
    df = make_flows()
    df.loc[0, " Label"] = "DDoS"
    clean, _ = clean_dataset(df)
    assert "DDoS" not in set(clean["Label"])


def test_conflicting_labels_detected():
    df = strip_column_names(make_flows(1, 1))
    df.loc[1, config.FEATURES] = df.loc[0, config.FEATURES].values
    assert conflicting_label_count(df) == 1


def test_fix_timestamps_moves_afternoon_hours():
    ts = fix_timestamps(pd.Series(["7/7/2017 1:00", "7/7/2017 3:29", "7/7/2017 9:15"]))
    assert list(ts.dt.hour) == [13, 15, 9]


def test_validate_columns_reports_missing():
    df = make_flows().drop(columns=[" SYN Flag Count"])
    assert validate_columns(df) == ["SYN Flag Count"]
    assert validate_columns(make_flows()) == []


def test_prepare_for_inference_skips_unusable_rows():
    df = make_flows()
    df.loc[2, " Flow Bytes/s"] = np.inf
    X, valid = prepare_for_inference(df)
    assert list(X.columns) == config.FEATURES
    assert len(X) == 5 and not valid.iloc[2]


def test_prepare_for_inference_rejects_wrong_file():
    with pytest.raises(ValueError, match="Missing required columns"):
        prepare_for_inference(pd.DataFrame({"a": [1]}))
