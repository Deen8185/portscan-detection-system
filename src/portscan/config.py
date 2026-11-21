"""Central settings for the AI-Based Port Scan Detection System.

Every module reads paths, feature names and labels from here, so the
dataset, the model and the dashboard always agree. The values follow the
design in Chapter Three of the project report.
"""

from pathlib import Path

# ---------------------------------------------------------------- paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLES_DIR = DATA_DIR / "samples"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"
TABLES_DIR = REPORTS_DIR / "tables"
DATABASE_PATH = DATA_DIR / "portscan.db"

# CICIDS2017 port scan capture (Friday 7 July 2017, afternoon).
RAW_DATASET_NAME = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
RAW_DATASET_PATH = RAW_DIR / RAW_DATASET_NAME

# ---------------------------------------------------------------- columns
# CICIDS2017 column names carry stray leading spaces; they are stripped
# on load, so the names below are the cleaned versions.
LABEL_COLUMN = "Label"
DESTINATION_PORT_COLUMN = "Destination Port"

BENIGN_LABEL = "BENIGN"
PORTSCAN_LABEL = "PortScan"
CLASS_NAMES = {0: BENIGN_LABEL, 1: PORTSCAN_LABEL}

# The 16 model features of Table 3.1. Destination Port is deliberately
# excluded: it is kept aside for the service discovery module, so the
# model learns scanning behaviour instead of memorising port numbers.
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]

# Columns an uploaded file must contain to be analysed.
REQUIRED_UPLOAD_COLUMNS = FEATURES + [DESTINATION_PORT_COLUMN]

# ---------------------------------------------------------------- training
RANDOM_STATE = 42
TEST_SIZE = 0.20        # 80:20 stratified split
CV_FOLDS = 5            # cross-validation folds for robustness checks
RF_N_ESTIMATORS = 100   # Random Forest with 100 trees
KNN_K = 5               # K-Nearest Neighbours with K = 5
SELECTION_METRIC = "f1"  # the model with the highest F1-score is kept

MODEL_PATH = MODELS_DIR / "best_model.joblib"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"
