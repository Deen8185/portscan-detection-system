"""Tests for flow-format detection and per-format model handling."""

import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from portscan import config, modeling
from portscan.formats import (CICIDS2017, PYTHON_COLUMNS, PYTHON_CICFLOWMETER,
                              detect_format, to_canonical)
from portscan.pipeline import InvalidFlowFile, analyse_flows

CANONICAL_TO_PYTHON = {v: k for k, v in PYTHON_COLUMNS.items()}


def cicids_row(value=1.0):
    return {" " + c: value for c in config.FEATURES} | {" Destination Port": 22}


def python_row(value=1.0):
    return {CANONICAL_TO_PYTHON[c]: value for c in config.FEATURES} | {
        "dst_port": 22, "src_ip": "10.10.0.1", "dst_ip": "10.10.0.2", "timestamp": "2026-11-22 08:00:00"}


def test_detects_cicids2017_layout():
    assert detect_format(pd.DataFrame([cicids_row()])) == CICIDS2017


def test_detects_python_cicflowmeter_layout():
    assert detect_format(pd.DataFrame([python_row()])) == PYTHON_CICFLOWMETER


def test_unknown_layout():
    assert detect_format(pd.DataFrame({"a": [1]})) is None


def test_python_columns_renamed_without_changing_values():
    df, fmt = to_canonical(pd.DataFrame([python_row(0.5)]))
    assert fmt == PYTHON_CICFLOWMETER
    assert set(config.REQUIRED_UPLOAD_COLUMNS) <= set(df.columns)
    assert df.loc[0, "Flow Duration"] == 0.5               # units are kept as exported
    assert df.loc[0, "Source IP"] == "10.10.0.1"


def test_every_model_feature_has_a_python_column():
    assert set(config.FEATURES) <= set(PYTHON_COLUMNS.values())


def test_pipeline_refuses_a_model_from_another_format():
    df = pd.DataFrame([python_row(), python_row(2.0)])
    model = DecisionTreeClassifier().fit(pd.DataFrame([[0] * 16, [1] * 16], columns=config.FEATURES), [0, 1])
    with pytest.raises(InvalidFlowFile, match="trained on"):
        analyse_flows(df, model=model, model_name="M", file_name="x.csv", model_format=CICIDS2017)
    result = analyse_flows(df, model=model, model_name="M", file_name="x.csv", model_format=PYTHON_CICFLOWMETER)
    assert result.flow_format == PYTHON_CICFLOWMETER and result.total_flows == 2


def test_model_paths_per_format():
    assert modeling.model_paths(CICIDS2017)[0] == config.MODEL_PATH
    assert modeling.model_paths(PYTHON_CICFLOWMETER)[0] == config.LAB_MODEL_PATH
    with pytest.raises(ValueError):
        modeling.model_paths("unknown")
