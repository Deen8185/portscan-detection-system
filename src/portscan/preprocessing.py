"""Loading, cleaning and feature preparation for network flow records.

Two kinds of data pass through this module:

* the CICIDS2017 training data, cleaned by :func:`clean_dataset`, which keeps a
  record of every step so the numbers can be reported in Chapter Four; and
* files uploaded to the dashboard, checked by :func:`validate_columns` and
  turned into model input by :func:`prepare_for_inference`.

Both paths use the same feature list and the same handling of missing and
infinite values, so the model sees data in the same form during training and
during detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from . import config

TARGET_COLUMN = "target"


# ---------------------------------------------------------------- loading
def strip_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """CICIDS2017 headers carry stray spaces (e.g. ' Destination Port')."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def load_raw_dataset(path: Path | str = config.RAW_DATASET_PATH) -> pd.DataFrame:
    """Read a CICFlowMeter CSV. Latin-1 tolerates the odd bytes in some
    CICIDS2017 files without failing."""
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    return strip_column_names(df)


def fix_timestamps(timestamps: pd.Series) -> pd.Series:
    """Parse CICIDS2017 timestamps and restore the missing afternoon hours.

    The files write times on a 12-hour clock without AM/PM, so the Friday
    afternoon capture (13:00-15:29) appears as 1:00-3:29. Capture days ran from
    about 8:00 to 17:00, so any hour before 8 belongs to the afternoon.
    """
    parsed = pd.to_datetime(timestamps, format="mixed", dayfirst=False)
    afternoon = parsed.dt.hour < 8
    return parsed.where(~afternoon, parsed + pd.Timedelta(hours=12))


# ---------------------------------------------------------------- cleaning
@dataclass
class CleaningStep:
    step: str
    rows_removed: int
    rows_remaining: int
    benign: int
    portscan: int


@dataclass
class CleaningReport:
    steps: list[CleaningStep] = field(default_factory=list)

    def record(self, step: str, before: int, df: pd.DataFrame) -> None:
        counts = df[config.LABEL_COLUMN].value_counts()
        self.steps.append(CleaningStep(
            step=step,
            rows_removed=before - len(df),
            rows_remaining=len(df),
            benign=int(counts.get(config.BENIGN_LABEL, 0)),
            portscan=int(counts.get(config.PORTSCAN_LABEL, 0)),
        ))

    def to_frame(self) -> pd.DataFrame:
        return pd.DataFrame([s.__dict__ for s in self.steps])


def to_numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return the model features as floats, with infinities turned into NaN.

    Flow Bytes/s and Flow Packets/s become infinite when CICFlowMeter divides
    by a zero flow duration, so infinity is treated the same as a missing value.
    """
    X = df[config.FEATURES].apply(pd.to_numeric, errors="coerce").astype("float64")
    return X.replace([np.inf, -np.inf], np.nan)


def clean_dataset(df: pd.DataFrame, deduplicate: bool = True) -> tuple[pd.DataFrame, CleaningReport]:
    """Clean CICIDS2017 flows for training, recording each step.

    Steps, following the recommendations of Engelen, Rimmer and Joosen (2021):

    1. keep only rows labelled BENIGN or PortScan;
    2. remove rows with missing or infinite feature values;
    3. remove rows with negative timing values, which are recording errors
       (Init_Win_bytes values of -1 are kept: CICFlowMeter uses -1 to mean
       "no window observed", which is genuine information);
    4. optionally remove duplicates, i.e. rows whose 16 model features and
       label are identical to an earlier row.

    Duplicates matter because identical rows can land in both the training and
    the testing set, so the model would be tested on records it has already
    seen. Removing them keeps the evaluation honest.
    """
    report = CleaningReport()
    df = strip_column_names(df)
    report.record("Raw dataset", len(df), df)

    before = len(df)
    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype(str).str.strip()
    df = df[df[config.LABEL_COLUMN].isin([config.BENIGN_LABEL, config.PORTSCAN_LABEL])]
    report.record("Keep BENIGN and PortScan labels only", before, df)

    before = len(df)
    numeric = to_numeric_features(df)
    df = df.assign(**{c: numeric[c] for c in config.FEATURES})
    df = df[numeric.notna().all(axis=1)]
    report.record("Remove missing or infinite values", before, df)

    before = len(df)
    timing = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean"]
    df = df[(df[timing] >= 0).all(axis=1)]
    report.record("Remove negative timing values", before, df)

    if deduplicate:
        before = len(df)
        df = df.drop_duplicates(subset=config.FEATURES + [config.LABEL_COLUMN])
        report.record("Remove duplicate feature records", before, df)

    df = df.copy()
    df[TARGET_COLUMN] = (df[config.LABEL_COLUMN] == config.PORTSCAN_LABEL).astype(int)
    return df.reset_index(drop=True), report


def conflicting_label_count(df: pd.DataFrame) -> int:
    """Number of distinct feature records that appear with both labels."""
    labels = df.groupby(config.FEATURES)[config.LABEL_COLUMN].nunique()
    return int((labels > 1).sum())


# ---------------------------------------------------------------- inference
def validate_columns(df: pd.DataFrame) -> list[str]:
    """Return the required columns missing from an uploaded file (empty if valid)."""
    present = set(strip_column_names(df).columns)
    return [c for c in config.REQUIRED_UPLOAD_COLUMNS if c not in present]


def prepare_for_inference(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Turn uploaded flow records into model input.

    Returns the feature matrix for the rows that can be classified and a
    boolean mask over the original rows saying which ones those are. Rows
    with missing or infinite feature values cannot be classified, and the
    dashboard reports how many were skipped.
    """
    df = strip_column_names(df)
    missing = validate_columns(df)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")
    X = to_numeric_features(df)
    valid = X.notna().all(axis=1)
    return X[valid], valid
