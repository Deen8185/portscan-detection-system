"""System test cases for Chapter Four (TC01-TC20).

Each test's docstring has the form

    TCnn | Title | Input | Expected result

and scripts/test_report.py turns them, with the pass/fail outcome, into the
test case table. Dashboard tests drive the real Streamlit app with
Streamlit's AppTest (uploads, clicks, page switches) against a temporary
database, so the real analysis history is never touched.

These tests need the trained model and the sample files
(scripts/train_models.py and scripts/make_samples.py); they are skipped
otherwise.
"""

from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from portscan import config, database
from portscan.modeling import evaluate
from portscan.pipeline import PREDICTION_COLUMN, InvalidFlowFile, analyse_flows
from portscan.service_discovery import NO_SCAN_MESSAGE

APP = config.PROJECT_ROOT / "app" / "Analyse.py"
SAMPLES = config.SAMPLES_DIR

pytestmark = pytest.mark.skipif(
    not (config.MODEL_PATH.exists() and (SAMPLES / "sample_mixed.csv").exists()),
    reason="needs the trained model and sample files")


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def model_meta():
    from portscan.modeling import load_model
    return load_model()


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    path = tmp_path / "system_test.db"
    monkeypatch.setattr(config, "DATABASE_PATH", path)
    return path


def read_sample(name):
    return pd.read_csv(SAMPLES / name, encoding="latin1", low_memory=False)


def analyse(df, model_meta, conn=None, name="test.csv"):
    model, meta = model_meta
    return analyse_flows(df, model=model, model_name=meta["model_name"], file_name=name, conn=conn)


def new_app():
    from streamlit.testing.v1 import AppTest
    return AppTest.from_file(str(APP), default_timeout=180).run()


def run_upload(at, filename, content: bytes, save=False):
    at.file_uploader[0].upload(filename, content, "text/csv").run()
    if not save:
        at.checkbox[0].uncheck().run()
    at.button[0].click().run()
    return at


def run_sample(at, name, save=False):
    at.radio[0].set_value("Use a sample file").run()
    at.selectbox[0].set_value(name).run()
    if not save:
        at.checkbox[0].uncheck().run()
    at.button[0].click().run()
    return at


def metrics(at):
    return {m.label: m.value for m in at.metric}


def count(value: str) -> int:
    return int(str(value).replace(",", ""))


def texts(elements):
    return " ".join(str(e.value) for e in elements)


# ---------------------------------------------------------------- dashboard
def test_tc01_dashboard_starts(temp_db):
    """TC01 | Dashboard start-up | Open the Analyse page | Page loads without errors; Analyse button stays disabled until a file is chosen"""
    at = new_app()
    assert not at.exception
    assert at.title[0].value == "Analyse Network Flows"
    assert at.button[0].disabled


def test_tc02_upload_mixed_file(temp_db):
    """TC02 | Detect scans in an uploaded file | Upload sample_mixed.csv (3,000 benign + 1,000 scan flows) | 4,000 flows analysed, about 1,000 flagged as port scan, alert lists the high-risk services probed"""
    at = run_upload(new_app(), "sample_mixed.csv", (SAMPLES / "sample_mixed.csv").read_bytes())
    assert not at.exception
    m = metrics(at)
    assert count(m["Flows analysed"]) == 4000
    assert 990 <= count(m["Port scan"]) <= 1010
    assert count(m["Benign"]) + count(m["Port scan"]) == 4000
    assert "Port scanning detected" in texts(at.error)
    assert count(m["High-risk services targeted"]) > 0


def test_tc03_benign_only_file(temp_db):
    """TC03 | No false alarms on normal traffic | Analyse sample_benign_only.csv (2,000 benign flows) | All flows classified benign; message 'No scanning activity detected'"""
    at = run_sample(new_app(), "sample_benign_only.csv")
    assert not at.exception
    assert count(metrics(at)["Port scan"]) == 0
    assert NO_SCAN_MESSAGE in texts(at.success)


def test_tc04_scan_only_file(model_meta):
    """TC04 | Detect a pure port scan | Analyse sample_scan_only.csv (500 scan flows) | At least 99% of flows flagged as port scan"""
    result = analyse(read_sample("sample_scan_only.csv"), model_meta)
    assert result.scan_flows / result.total_flows >= 0.99


def test_tc05_wrong_file_rejected(temp_db):
    """TC05 | Reject a file of the wrong type | Upload a CSV without flow columns (sample_invalid.csv) | Error naming the missing columns; nothing saved to the history"""
    at = run_upload(new_app(), "sample_invalid.csv", (SAMPLES / "sample_invalid.csv").read_bytes(), save=True)
    assert not at.exception
    msg = texts(at.error)
    assert "cannot be analysed" in msg and "Flow Duration" in msg
    with database.open_db(temp_db) as conn:
        assert database.list_analyses(conn).empty


def test_tc06_empty_file_rejected(temp_db):
    """TC06 | Reject an empty file | Upload a 0-byte CSV file | Error 'not a readable CSV file'; the application does not crash"""
    at = run_upload(new_app(), "empty.csv", b"")
    assert not at.exception
    assert "not a readable CSV file" in texts(at.error)


def test_tc07_header_only_file(model_meta):
    """TC07 | Reject a file with no flow rows | A CSV with the correct header but no rows | Clear error that no rows could be analysed"""
    header_only = read_sample("sample_mixed.csv").iloc[:0]
    with pytest.raises(InvalidFlowFile, match="None of the rows"):
        analyse(header_only, model_meta)


def test_tc08_invalid_rows_skipped(model_meta):
    """TC08 | Skip unusable rows | sample_mixed.csv with 10 rows given infinite or missing values | The 10 rows are skipped and reported; the other 3,990 are analysed"""
    df = read_sample("sample_mixed.csv")
    col = {c.strip(): c for c in df.columns}           # real header names (some have leading spaces)
    df.loc[:4, col["Flow Bytes/s"]] = np.inf
    df.loc[5:9, col["Flow IAT Mean"]] = np.nan
    result = analyse(df, model_meta)
    assert result.skipped_flows == 10 and result.total_flows == 3990


def test_tc09_column_order_and_extras(model_meta):
    """TC09 | Accept different column layouts | Same flows with columns shuffled, an extra column added and header spaces removed | Identical predictions to the original file"""
    df = read_sample("sample_mixed.csv")
    original = analyse(df, model_meta).flows[PREDICTION_COLUMN].reset_index(drop=True)
    changed = df.sample(frac=1.0, axis=1, random_state=1).assign(Notes="extra")
    changed.columns = changed.columns.str.strip()
    again = analyse(changed, model_meta).flows[PREDICTION_COLUMN].reset_index(drop=True)
    assert original.equals(again)


def test_tc10_machine_learning_csv_format(model_meta):
    """TC10 | Accept files without address columns | Flows with Flow ID, IP addresses, source port, protocol and timestamp removed (MachineLearningCSV layout) | Analysis succeeds; services found; targeted-host table left empty"""
    df = read_sample("sample_mixed.csv")
    drop = [c for c in df.columns if c.strip() in
            ("Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp")]
    result = analyse(df.drop(columns=drop), model_meta)
    assert result.scan_flows > 0 and result.discovery.found
    assert result.hosts.empty


def test_tc11_saved_analysis_in_history(temp_db):
    """TC11 | Save an analysis to the history | Analyse sample_mixed.csv with 'Save' ticked, then open the History page | History lists the analysis with the same flow and scan counts"""
    at = run_sample(new_app(), "sample_mixed.csv", save=True)
    scans = count(metrics(at)["Port scan"])
    at.switch_page("pages/1_History.py").run()
    assert not at.exception
    history = at.dataframe[0].value
    assert len(history) == 1
    row = history.iloc[0]
    assert row["file_name"] == "sample_mixed.csv" and int(row["scan_flows"]) == scans
    assert int(row["total_flows"]) == 4000


def test_tc12_unsaved_analysis_not_stored(temp_db):
    """TC12 | Analyse without saving | Analyse sample_mixed.csv with 'Save' unticked | History stays empty"""
    run_sample(new_app(), "sample_mixed.csv", save=False)
    with database.open_db(temp_db) as conn:
        assert database.list_analyses(conn).empty


def test_tc13_delete_analysis(model_meta, temp_db):
    """TC13 | Delete an analysis | Save one analysis, then delete it | The analysis and all its targeted services are removed"""
    with database.open_db(temp_db) as conn:
        result = analyse(read_sample("sample_scan_only.csv"), model_meta, conn=conn)
        assert len(database.get_targeted_services(conn, result.log_id)) > 0
        assert database.delete_analysis(conn, result.log_id)
        assert database.list_analyses(conn).empty
        assert conn.execute("SELECT COUNT(*) FROM targeted_services").fetchone()[0] == 0


def test_tc14_service_discovery_mapping(model_meta):
    """TC14 | Map scanned ports to services | Scan flows aimed at ports 22, 3389 and 1107 | 22 shown as SSH (Medium), 3389 as RDP (High), 1107 as Unknown service"""
    scans = read_sample("sample_scan_only.csv")
    scans = pd.concat([scans.head(3)] * 1, ignore_index=True)
    scans[" Destination Port"] = [22, 3389, 1107]
    services = analyse(scans, model_meta).discovery.services.set_index("port")
    assert services.loc[22, "service"] == "SSH" and services.loc[22, "risk_level"] == "Medium"
    assert services.loc[3389, "service"] == "RDP" and services.loc[3389, "risk_level"] == "High"
    assert services.loc[1107, "service"] == "Unknown service"


def test_tc15_report_downloads(model_meta, temp_db):
    """TC15 | Download the report | Analyse sample_mixed.csv and use the download buttons | Three CSV downloads; flagged-flows report has one row per detected scan with a Prediction column"""
    at = run_sample(new_app(), "sample_mixed.csv")
    assert len(at.download_button) == 3
    result = analyse(read_sample("sample_mixed.csv"), model_meta)
    report = pd.read_csv(StringIO(result.flagged.to_csv(index=False)))
    assert len(report) == result.scan_flows and set(report[PREDICTION_COLUMN]) == {"PortScan"}


def test_tc16_model_performance_page(temp_db, model_meta):
    """TC16 | Show model performance | Open the Model Performance page | Page loads; displayed F1-score and recall match the saved model's test results"""
    _, meta = model_meta
    at = new_app()
    at.switch_page("pages/2_Model_Performance.py").run()
    assert not at.exception
    m = metrics(at)
    assert m["F1-score"] == f"{meta['test_metrics']['f1']:.4f}"
    assert m["Recall (detection rate)"] == f"{meta['test_metrics']['recall']:.4f}"


def test_tc17_service_map_search(temp_db):
    """TC17 | Search the service map | Open the Service Map page and search for '3389' | Exactly one row: RDP, High risk"""
    at = new_app()
    at.switch_page("pages/3_Service_Map.py").run()
    at.text_input[0].set_value("3389").run()
    assert not at.exception
    table = at.dataframe[0].value
    table = getattr(table, "data", table)          # styled table -> underlying data
    assert len(table) == 1 and table.iloc[0]["service"] == "RDP" and table.iloc[0]["risk_level"] == "High"


def test_tc18_held_out_accuracy(model_meta):
    """TC18 | Detection accuracy on unseen data | The 22,431 held-out test records (329 port scans) | F1-score at least 0.98 and false positive rate at most 0.1%"""
    model, _ = model_meta
    test = pd.read_csv(config.PROCESSED_DIR / "test_set.csv")
    m = evaluate(test["target"], model.predict(test[config.FEATURES]))
    assert m["f1"] >= 0.98 and m["fpr"] <= 0.001


def test_tc19_repeatable_results(model_meta):
    """TC19 | Repeatable results | Analyse sample_mixed.csv twice | Both runs give identical predictions and services"""
    df = read_sample("sample_mixed.csv")
    a, b = analyse(df, model_meta), analyse(df, model_meta)
    assert a.flows[PREDICTION_COLUMN].equals(b.flows[PREDICTION_COLUMN])
    assert a.discovery.services.equals(b.discovery.services)


def test_tc20_high_risk_alert_contents(temp_db):
    """TC20 | Warn about high-risk services | Analyse sample_scan_only.csv | Alert names the high-risk services probed, e.g. FTP, SMB or RDP, with their ports"""
    at = run_sample(new_app(), "sample_scan_only.csv")
    alert = texts(at.error)
    assert "high-risk service" in alert
    assert any(f"{name} (" in alert for name in ("FTP", "SMB", "RDP", "Telnet", "MySQL", "MS-SQL", "Oracle", "NFS"))
