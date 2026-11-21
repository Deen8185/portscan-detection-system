"""SQLite storage for the service map and the history of analyses.

The three tables follow Section 3.3.4:

* service_map (Table 3.2): the port-to-service mapping, filled from
  service_map.SERVICE_MAP;
* detection_log (Table 3.3): one row per analysed file;
* targeted_services (Table 3.4): the services found in each analysis,
  linked to detection_log through log_id.

SQLite was chosen because it needs no separate server and is built into
Python. Deleting an analysis also deletes its targeted services.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pandas as pd

from . import config
from .service_map import SERVICE_MAP

SCHEMA = """
CREATE TABLE IF NOT EXISTS service_map (
    port         INTEGER PRIMARY KEY CHECK (port BETWEEN 0 AND 65535),
    protocol     TEXT    NOT NULL,
    service      TEXT    NOT NULL,
    description  TEXT,
    risk_level   TEXT    NOT NULL CHECK (risk_level IN ('High', 'Medium', 'Low'))
);

CREATE TABLE IF NOT EXISTS detection_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    file_name     TEXT    NOT NULL,
    total_flows   INTEGER NOT NULL CHECK (total_flows >= 0),
    benign_flows  INTEGER NOT NULL CHECK (benign_flows >= 0),
    scan_flows    INTEGER NOT NULL CHECK (scan_flows >= 0),
    model_used    TEXT    NOT NULL,
    CHECK (benign_flows + scan_flows = total_flows)
);

CREATE TABLE IF NOT EXISTS targeted_services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id      INTEGER NOT NULL REFERENCES detection_log(log_id) ON DELETE CASCADE,
    port        INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    service     TEXT    NOT NULL,
    risk_level  TEXT    NOT NULL CHECK (risk_level IN ('High', 'Medium', 'Low', 'Unknown')),
    hit_count   INTEGER NOT NULL CHECK (hit_count > 0)
);

CREATE INDEX IF NOT EXISTS idx_targeted_services_log ON targeted_services(log_id);
"""


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """Open the database, creating the tables and the service map if needed.

    The default location is read when the function is called (not when the
    module is imported), so tests can point config.DATABASE_PATH elsewhere.
    """
    path = path or config.DATABASE_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    seed_service_map(conn)


def seed_service_map(conn: sqlite3.Connection) -> int:
    """Insert or update every entry of the service map; returns the row count."""
    with conn:
        conn.executemany(
            "INSERT INTO service_map (port, protocol, service, description, risk_level) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(port) DO UPDATE SET protocol = excluded.protocol, service = excluded.service, "
            "description = excluded.description, risk_level = excluded.risk_level",
            SERVICE_MAP)
    return conn.execute("SELECT COUNT(*) FROM service_map").fetchone()[0]


def get_service_map(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM service_map ORDER BY port", conn)


def save_analysis(conn: sqlite3.Connection, *, file_name: str, total_flows: int,
                  benign_flows: int, scan_flows: int, model_used: str,
                  services: pd.DataFrame, timestamp: datetime | None = None) -> int:
    """Store one analysis and its targeted services in a single transaction.

    ``services`` is the table returned by service discovery (columns port,
    service, risk_level and hit_count). Returns the new log_id.
    """
    ts = (timestamp or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    with conn:  # commits on success, rolls back everything on any error
        cur = conn.execute(
            "INSERT INTO detection_log (timestamp, file_name, total_flows, benign_flows, scan_flows, model_used) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, file_name[:100], int(total_flows), int(benign_flows), int(scan_flows), model_used))
        log_id = cur.lastrowid
        if not services.empty:
            rows = [(log_id, int(r.port), str(r.service), str(r.risk_level), int(r.hit_count))
                    for r in services.itertuples(index=False)]
            conn.executemany(
                "INSERT INTO targeted_services (log_id, port, service, risk_level, hit_count) "
                "VALUES (?, ?, ?, ?, ?)", rows)
    return log_id


def list_analyses(conn: sqlite3.Connection) -> pd.DataFrame:
    """All past analyses, newest first, with their number of targeted ports
    and high-risk ports."""
    return pd.read_sql_query(
        """
        SELECT d.log_id, d.timestamp, d.file_name, d.total_flows, d.benign_flows, d.scan_flows,
               d.model_used,
               COUNT(t.id) AS targeted_ports,
               COALESCE(SUM(t.risk_level = 'High'), 0) AS high_risk_ports
        FROM detection_log d LEFT JOIN targeted_services t ON t.log_id = d.log_id
        GROUP BY d.log_id
        ORDER BY d.log_id DESC
        """, conn)


def get_analysis(conn: sqlite3.Connection, log_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM detection_log WHERE log_id = ?", (log_id,)).fetchone()
    if row is None:
        return None
    cols = [c[0] for c in conn.execute("SELECT * FROM detection_log LIMIT 0").description]
    return dict(zip(cols, row))


def get_targeted_services(conn: sqlite3.Connection, log_id: int) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT port, service, risk_level, hit_count FROM targeted_services "
        "WHERE log_id = ? ORDER BY hit_count DESC, "
        "CASE risk_level WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END, port",
        conn, params=(log_id,))


def delete_analysis(conn: sqlite3.Connection, log_id: int) -> bool:
    """Delete one analysis (its targeted services go with it)."""
    with conn:
        cur = conn.execute("DELETE FROM detection_log WHERE log_id = ?", (log_id,))
    return cur.rowcount > 0


@contextmanager
def open_db(path: Path | str | None = None):
    conn = connect(path)
    try:
        yield conn
    finally:
        conn.close()
