@echo off
rem Start the port scan detection dashboard (double-click this file).
rem It opens at http://localhost:8501 in your browser.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo The Python environment is missing. See README.md, "Setup".
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m streamlit run app\Analyse.py --server.port 8501 %*
