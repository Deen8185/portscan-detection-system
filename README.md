# AI-Based Port Scan Detection System for Intelligent Service Discovery

A final-year project system that classifies network flows as **benign** or
**port scan** with supervised machine learning, then maps the ports targeted by
detected scans to the services behind them (for example 22 → SSH, 3389 → RDP).
It is built for administrators of university and departmental networks.

## Project layout

```
portscan_detector/
├── app/                 Streamlit web dashboard (pages/ holds extra pages)
├── data/
│   ├── raw/             CICIDS2017 CSV goes here (not committed)
│   ├── processed/       Cleaned data produced by the pipeline
│   └── samples/         Small test files for uploading to the dashboard
├── models/              Trained model and its metadata
├── reports/
│   ├── figures/         Charts for Chapter Four (confusion matrices, etc.)
│   └── tables/          Result tables for Chapter Four
├── scripts/             Command-line steps: prepare data, train, evaluate
├── src/portscan/        The system's code (config, preprocessing, model,
│                        service discovery, database)
└── tests/               Automated tests
```

## Setup (Windows PowerShell)

```powershell
cd "portscan_detector"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
pytest
```

## Running the system

1. `python scripts/prepare_data.py`: clean the dataset
2. `python scripts/train_models.py`: train and evaluate the models (about 4 minutes)
3. `python scripts/make_samples.py`: create sample files for the dashboard
4. Double-click `run_dashboard.cmd` (or run `streamlit run app/Analyse.py`); the dashboard opens at http://localhost:8501

The dashboard has four pages: **Analyse** (upload flows, see detections and targeted services, download reports), **History** (saved analyses), **Model Performance** and **Service Map**.

## Lab: own traffic (Phase 7)

The `lab/` folder builds an isolated network inside Ubuntu on WSL, using Linux
network namespaces. A scanner (10.10.0.1) and a normal user (10.10.0.3) talk to a
target (10.10.0.2) that runs FTP, SSH, HTTP and MySQL, and everything is recorded
on a virtual bridge. Nothing is reachable from outside the computer. **Only scan
machines you own or are authorised to test.**

```
wsl -u root -- bash lab/install_lab.sh     # once: tools and target services
wsl -u root -- bash lab/record_all.sh      # about 50 minutes; resumable
python scripts/train_lab_model.py          # train and evaluate the lab model
```

Flows are produced with the Python CICFlowMeter 0.5. It computes some features
(durations, packet lengths and TCP flag counts) differently from the 2017 tool
behind CICIDS2017, so the CICIDS2017 model detects none of the lab scans. A second
model was therefore trained on the lab's training scenarios and tested on held-out
scenarios. The dashboard recognises each file's format and uses the matching model.

| Held-out scenario | Lab model | Threshold detector | CICIDS2017 model |
|---|---|---|---|
| Real slow scan (15 s between probes) | 1.00 | 0.00 | 0.00 |
| FIN scan | 1.00 | 1.00 (43 false alarms) | 0.00 |
| All 65,535 ports | 1.00 | 1.00 | 0.00 |
| UDP scan | 0.75 | 1.00 (44 false alarms) | 0.00 |
| Service/version scan | 0.71 | 0.94 | 0.00 |
| Normal use only | 0 false alarms | 0 false alarms | 0 false alarms |

Values are recall (share of scan flows detected). The lab model raised no false
alarms on any of the 1,381 normal test flows.

## Dataset

The system uses the port scan capture from **CICIDS2017** (Canadian Institute for
Cybersecurity, University of New Brunswick): the file
`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`.

Download it from https://www.unb.ca/cic/datasets/ids-2017.html. The
**GeneratedLabelledFlows** version is preferred, because it also contains
Source IP and Timestamp columns, which the threshold-based comparison
needs. The MachineLearningCSV version works for the model alone.

Place the file in `data/raw/`.

## Build phases

| Phase | Content | Status |
|---|---|---|
| 0 | Project setup | Done |
| 1 | Data loading, cleaning and exploration (`python scripts/prepare_data.py`) | Done |
| 2 | Model training and evaluation (`python scripts/train_models.py`, about 4 minutes) | Done |
| 3 | Service discovery module (`python scripts/discover_services.py`) | Done |
| 4 | SQLite database and analysis pipeline (`python scripts/init_db.py`) | Done |
| 5 | Streamlit dashboard (`run_dashboard.cmd` or `streamlit run app/Analyse.py`) | Done |
| 6 | Testing (`python scripts/test_report.py`, `python scripts/performance_test.py`) | Done |
| 7 | Lab with own traffic and a lab model (`lab/`, `python scripts/train_lab_model.py`) | Done |
