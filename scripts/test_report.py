"""Phase 6: run all tests and write the test tables for Chapter Four.

Run from the project folder:
    python scripts/test_report.py

Outputs
    reports/tables/system_test_cases.csv / .md   TC01-TC20 with input,
                                                 expected and actual result
    reports/tables/unit_test_summary.csv / .md   tests per module
"""

import ast
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import pandas as pd

from portscan import config

TESTS = config.PROJECT_ROOT / "tests"
JUNIT = config.REPORTS_DIR / "test_results.xml"
MODULES = {
    "test_setup.py": "Project setup and settings",
    "test_preprocessing.py": "Data loading, cleaning and input checks",
    "test_modeling.py": "Model training, evaluation, selection and threshold baseline",
    "test_service_discovery.py": "Service map and service discovery",
    "test_database.py": "Database and end-to-end analysis pipeline",
    "test_system.py": "System test cases TC01-TC20 (including the dashboard)",
}


def markdown(df: pd.DataFrame) -> str:
    """Plain Markdown table (no extra packages needed)."""
    def cell(v):
        return str(v).replace("|", "/").replace("\n", " ")
    lines = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines)


def docstrings(path):
    tree = ast.parse(path.read_text(encoding="utf8"))
    return {n.name: ast.get_docstring(n) or "" for n in tree.body if isinstance(n, ast.FunctionDef)}


def main():
    print("Running the test suite ...", flush=True)
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", f"--junitxml={JUNIT}"],
                          cwd=config.PROJECT_ROOT, capture_output=True, text=True)
    print(proc.stdout.strip().splitlines()[-1])

    results = []
    for case in ET.parse(JUNIT).getroot().iter("testcase"):
        failure = case.find("failure") if case.find("failure") is not None else case.find("error")
        skipped = case.find("skipped")
        status = "Failed" if failure is not None else "Skipped" if skipped is not None else "Passed"
        detail = (failure.get("message") or "").splitlines()[0][:200] if failure is not None else ""
        results.append({"file": case.get("classname").split(".")[-1] + ".py",
                        "name": case.get("name").split("[")[0],
                        "seconds": float(case.get("time", 0)), "status": status, "detail": detail})
    res = pd.DataFrame(results)

    # ---- system test cases
    docs = docstrings(TESTS / "test_system.py")
    rows = []
    for r in res[res["file"] == "test_system.py"].itertuples():
        parts = [p.strip() for p in docs.get(r.name, "").split("|")]
        if len(parts) != 4:
            continue
        tc, title, given, expected = parts
        actual = {"Passed": "As expected", "Skipped": "Not run (model or samples missing)"}.get(
            r.status, f"Not as expected: {r.detail}")
        rows.append({"Test ID": tc, "Test case": title, "Input": given, "Expected result": expected,
                     "Actual result": actual, "Status": "Pass" if r.status == "Passed" else r.status})
    cases = pd.DataFrame(rows).sort_values("Test ID")
    cases.to_csv(config.TABLES_DIR / "system_test_cases.csv", index=False)

    # ---- unit test summary per module
    summary = (res.groupby("file")
               .agg(tests=("name", "size"), passed=("status", lambda s: (s == "Passed").sum()),
                    failed=("status", lambda s: (s == "Failed").sum()),
                    skipped=("status", lambda s: (s == "Skipped").sum()), seconds=("seconds", "sum"))
               .reset_index())
    summary.insert(1, "covers", summary["file"].map(MODULES))
    summary["order"] = summary["file"].map(list(MODULES).index)
    summary = summary.sort_values("order").drop(columns="order")
    total = pd.DataFrame([{"file": "Total", "covers": "", **summary[["tests", "passed", "failed", "skipped", "seconds"]].sum()}])
    summary = pd.concat([summary, total], ignore_index=True)
    summary[["tests", "passed", "failed", "skipped"]] = summary[["tests", "passed", "failed", "skipped"]].astype(int)
    summary["seconds"] = summary["seconds"].round(1)
    summary.to_csv(config.TABLES_DIR / "unit_test_summary.csv", index=False)

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    (config.TABLES_DIR / "system_test_cases.md").write_text(
        f"# System test cases\n\nRun on {stamp}: {int((cases['Status'] == 'Pass').sum())} of {len(cases)} passed.\n\n"
        + markdown(cases) + "\n", encoding="utf8")
    (config.TABLES_DIR / "unit_test_summary.md").write_text(
        f"# Automated test summary\n\nRun on {stamp}.\n\n" + markdown(summary) + "\n", encoding="utf8")

    print(f"\nSystem test cases: {int((cases['Status'] == 'Pass').sum())} of {len(cases)} passed")
    print(cases[["Test ID", "Test case", "Status"]].to_string(index=False))
    print("\nTests per module")
    print(summary.to_string(index=False))
    JUNIT.unlink(missing_ok=True)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
