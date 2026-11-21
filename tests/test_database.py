"""Tests for the SQLite database and the end-to-end analysis pipeline."""

import sqlite3
from datetime import datetime

import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from portscan import config, database
from portscan.pipeline import (PREDICTION_COLUMN, PROBABILITY_COLUMN,
                               InvalidFlowFile, analyse_flows)
from portscan.service_map import SERVICE_MAP


@pytest.fixture
def conn(tmp_path):
    c = database.connect(tmp_path / "test.db")
    yield c
    c.close()


def services_df(rows):
    return pd.DataFrame(rows, columns=["port", "service", "risk_level", "hit_count"])


# ---------------------------------------------------------------- schema
def test_tables_match_chapter_three(conn):
    cols = lambda t: [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
    assert cols("service_map") == ["port", "protocol", "service", "description", "risk_level"]
    assert cols("detection_log") == ["log_id", "timestamp", "file_name", "total_flows",
                                     "benign_flows", "scan_flows", "model_used"]
    assert cols("targeted_services") == ["id", "log_id", "port", "service", "risk_level", "hit_count"]


def test_service_map_is_seeded_once(conn, tmp_path):
    assert len(database.get_service_map(conn)) == len(SERVICE_MAP)
    database.seed_service_map(conn)                       # re-seeding must not duplicate
    assert len(database.get_service_map(conn)) == len(SERVICE_MAP)
    again = database.connect(tmp_path / "test.db")        # nor reconnecting
    assert len(database.get_service_map(again)) == len(SERVICE_MAP)
    again.close()


# ---------------------------------------------------------------- history
def test_save_and_read_analysis(conn):
    log_id = database.save_analysis(
        conn, file_name="lab.csv", total_flows=10, benign_flows=7, scan_flows=3,
        model_used="Random Forest", timestamp=datetime(2026, 11, 21, 14, 30),
        services=services_df([(22, "SSH", "Medium", 2), (3389, "RDP", "High", 1)]))
    log = database.get_analysis(conn, log_id)
    assert log["timestamp"] == "2026-11-21 14:30:00" and log["scan_flows"] == 3
    svc = database.get_targeted_services(conn, log_id)
    assert list(svc["port"]) == [22, 3389]
    history = database.list_analyses(conn)
    assert history.loc[0, "targeted_ports"] == 2 and history.loc[0, "high_risk_ports"] == 1


def test_stored_services_keep_discovery_order(conn):
    log_id = database.save_analysis(
        conn, file_name="tie.csv", total_flows=3, benign_flows=0, scan_flows=3, model_used="RF",
        services=services_df([(443, "HTTPS", "Low", 1), (1107, "Unknown service", "Unknown", 1),
                              (3389, "RDP", "High", 1)]))
    assert list(database.get_targeted_services(conn, log_id)["port"]) == [3389, 443, 1107]


def test_history_is_newest_first(conn):
    for name in ("first.csv", "second.csv"):
        database.save_analysis(conn, file_name=name, total_flows=1, benign_flows=1, scan_flows=0,
                               model_used="RF", services=services_df([]))
    assert list(database.list_analyses(conn)["file_name"]) == ["second.csv", "first.csv"]


def test_analysis_without_scans_has_no_services(conn):
    log_id = database.save_analysis(conn, file_name="clean.csv", total_flows=5, benign_flows=5,
                                    scan_flows=0, model_used="RF", services=services_df([]))
    assert database.get_targeted_services(conn, log_id).empty
    assert database.list_analyses(conn).loc[0, "high_risk_ports"] == 0


def test_delete_removes_services_too(conn):
    log_id = database.save_analysis(conn, file_name="x.csv", total_flows=1, benign_flows=0,
                                    scan_flows=1, model_used="RF",
                                    services=services_df([(23, "Telnet", "High", 1)]))
    assert database.delete_analysis(conn, log_id)
    assert database.get_analysis(conn, log_id) is None
    assert conn.execute("SELECT COUNT(*) FROM targeted_services").fetchone()[0] == 0
    assert not database.delete_analysis(conn, log_id)


def test_inconsistent_counts_are_rejected_and_nothing_is_saved(conn):
    with pytest.raises(sqlite3.IntegrityError):
        database.save_analysis(conn, file_name="bad.csv", total_flows=10, benign_flows=5,
                               scan_flows=1, model_used="RF", services=services_df([]))
    assert database.list_analyses(conn).empty


def test_failed_service_insert_rolls_back_the_log(conn):
    with pytest.raises(sqlite3.IntegrityError):
        database.save_analysis(conn, file_name="bad.csv", total_flows=1, benign_flows=0,
                               scan_flows=1, model_used="RF",
                               services=services_df([(22, "SSH", "Severe", 1)]))  # invalid risk
    assert database.list_analyses(conn).empty


# ---------------------------------------------------------------- pipeline
def flow_file(n_benign=20, n_scan=10):
    """A small upload in CICFlowMeter shape, with leading spaces in headers."""
    rng = np.random.default_rng(1)
    rows = []
    for _ in range(n_benign):
        rows.append({f: float(rng.normal(1000, 50)) for f in config.FEATURES} | {"Destination Port": 443})
    for i in range(n_scan):
        rows.append({f: float(rng.normal(2, 0.5)) for f in config.FEATURES}
                    | {"Destination Port": [22, 23, 3389][i % 3]})
    df = pd.DataFrame(rows)
    df.columns = [" " + c for c in df.columns]
    return df


@pytest.fixture
def toy_model():
    df = flow_file()
    df.columns = df.columns.str.strip()
    y = [0] * 20 + [1] * 10
    return DecisionTreeClassifier(random_state=0).fit(df[config.FEATURES], y)


def test_pipeline_end_to_end(conn, toy_model):
    upload = flow_file()
    upload.loc[0, " Flow Bytes/s"] = np.inf                  # one unusable row
    result = analyse_flows(upload, model=toy_model, model_name="Toy tree",
                           file_name="upload.csv", conn=conn)
    assert result.skipped_flows == 1 and result.total_flows == 29
    assert result.scan_flows == 10 and result.benign_flows == 19
    assert set(result.flows[PREDICTION_COLUMN]) == {"BENIGN", "PortScan"}
    assert PROBABILITY_COLUMN in result.flows
    assert set(result.discovery.services["port"]) == {22, 23, 3389}
    saved = database.list_analyses(conn).iloc[0]
    assert saved.log_id == result.log_id and saved.scan_flows == 10 and saved.high_risk_ports == 2


def test_pipeline_without_database(toy_model):
    result = analyse_flows(flow_file(), model=toy_model, model_name="Toy", file_name="f.csv")
    assert result.log_id is None and result.scan_flows == 10


def test_pipeline_rejects_wrong_file(toy_model):
    with pytest.raises(InvalidFlowFile, match="missing"):
        analyse_flows(pd.DataFrame({"name": ["a"]}), model=toy_model, model_name="T", file_name="x.csv")


def test_pipeline_rejects_file_with_no_usable_rows(toy_model):
    upload = flow_file(2, 0)
    upload[" Flow Bytes/s"] = np.inf
    with pytest.raises(InvalidFlowFile, match="None of the rows"):
        analyse_flows(upload, model=toy_model, model_name="T", file_name="x.csv")
