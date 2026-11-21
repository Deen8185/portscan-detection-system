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
| 7 | Optional live demo with own capture | Pending |
