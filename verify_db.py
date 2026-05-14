"""Phase 2 smoke test: create the schema and inspect what landed in Postgres."""
from __future__ import annotations

from sqlalchemy import inspect, text

import models  # noqa: F401 - registers models on Base.metadata
from database import Base, engine


def main() -> None:
    print(f"Connecting to: {engine.url.render_as_string(hide_password=True)}")

    with engine.connect() as conn:
        version = conn.execute(text("SELECT version()")).scalar_one()
        print(f"Server: {version}\n")

    print("Running Base.metadata.create_all() ...")
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"Tables now in database: {tables}\n")

    for table in ("scans_history", "indicators_cache"):
        if table not in tables:
            print(f"  MISSING: {table}")
            continue
        print(f"  {table}:")
        for col in inspector.get_columns(table):
            nullable = "NULL" if col["nullable"] else "NOT NULL"
            print(f"    - {col['name']}: {col['type']} {nullable}")
        for idx in inspector.get_indexes(table):
            print(f"    index {idx['name']} on {idx['column_names']}")
        for uc in inspector.get_unique_constraints(table):
            print(f"    unique {uc['name']} on {uc['column_names']}")
        print()


if __name__ == "__main__":
    main()
