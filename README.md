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
| 3 | Service discovery module | Pending |
| 4 | SQLite database | Pending |
| 5 | Streamlit dashboard | Pending |
| 6 | Testing | Pending |
| 7 | Optional live demo with own capture | Pending |
