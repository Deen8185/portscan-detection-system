"""One analysis from start to finish, as in the sequence diagram (Figure 3.3):

uploaded flows -> pre-processing -> detection model -> service discovery
-> saved summary in the database -> results for the dashboard.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

import pandas as pd

from . import config
from .database import save_analysis
from .preprocessing import prepare_for_inference, strip_column_names, validate_columns
from .service_discovery import DiscoveryResult, discover_services, targeted_hosts

PREDICTION_COLUMN = "Prediction"
PROBABILITY_COLUMN = "Scan probability"


class InvalidFlowFile(ValueError):
    """The uploaded file is not a CICFlowMeter flow file the system can analyse."""


@dataclass
class AnalysisResult:
    flows: pd.DataFrame          # analysed rows plus Prediction and Scan probability
    skipped_flows: int           # rows with missing or infinite values
    discovery: DiscoveryResult
    hosts: pd.DataFrame
    model_used: str
    log_id: int | None = None

    @property
    def total_flows(self) -> int:
        return len(self.flows)

    @property
    def scan_flows(self) -> int:
        return int((self.flows[PREDICTION_COLUMN] == config.PORTSCAN_LABEL).sum())

    @property
    def benign_flows(self) -> int:
        return self.total_flows - self.scan_flows

    @property
    def flagged(self) -> pd.DataFrame:
        return self.flows[self.flows[PREDICTION_COLUMN] == config.PORTSCAN_LABEL]


def analyse_flows(df: pd.DataFrame, *, model, model_name: str, file_name: str,
                  conn: sqlite3.Connection | None = None) -> AnalysisResult:
    """Classify every flow, discover targeted services and (if a database
    connection is given) store the summary. Raises InvalidFlowFile when the
    file lacks required columns or has no usable rows."""
    df = strip_column_names(df)
    missing = validate_columns(df)
    if missing:
        raise InvalidFlowFile(
            f"The file is missing {len(missing)} required column(s): {', '.join(missing)}. "
            "Upload a flow file produced by CICFlowMeter.")
    X, valid = prepare_for_inference(df)
    if X.empty:
        raise InvalidFlowFile("None of the rows in the file could be analysed "
                              "(all contain missing or infinite values).")

    flows = df.loc[valid].copy()
    pred = model.predict(X)
    flows[PREDICTION_COLUMN] = pd.Series(pred, index=flows.index).map(config.CLASS_NAMES)
    if hasattr(model, "predict_proba"):
        flows[PROBABILITY_COLUMN] = model.predict_proba(X)[:, 1].round(4)

    discovery = discover_services(flows, pred)
    result = AnalysisResult(flows=flows, skipped_flows=int((~valid).sum()), discovery=discovery,
                            hosts=targeted_hosts(flows, pred), model_used=model_name)
    if conn is not None:
        result.log_id = save_analysis(
            conn, file_name=file_name, total_flows=result.total_flows,
            benign_flows=result.benign_flows, scan_flows=result.scan_flows,
            model_used=model_name, services=discovery.services)
    return result
