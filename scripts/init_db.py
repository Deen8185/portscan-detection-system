"""Phase 4: create the SQLite database and fill the service map.

Run from the project folder:
    python scripts/init_db.py

Safe to run again: tables are only created if missing and the service map
is updated in place, so analysis history is kept.
"""

from portscan import config, database


def main():
    with database.open_db() as conn:
        services = database.get_service_map(conn)
        history = database.list_analyses(conn)
        print(f"Database: {config.DATABASE_PATH.relative_to(config.PROJECT_ROOT).as_posix()}")
        for table in ("service_map", "detection_log", "targeted_services"):
            n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table:<18} {n:>5} rows")
        print("\nService map by risk level")
        print(services["risk_level"].value_counts().to_string())
        print(f"\nStored analyses: {len(history)}")


if __name__ == "__main__":
    main()
