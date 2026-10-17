"""
SQLite Database Setup for Audit Logs and Security Event History.
Stores metadata, hashes, and risk indicators without retaining raw sensitive user bodies.
"""

import sqlite3
from pathlib import Path
from contextlib import contextmanager
from backend.config import SQLITE_DB_PATH


def init_db():
    """Initializes audit database table schema."""
    SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(SQLITE_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                input_type TEXT NOT NULL,
                content_length INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                content_preview TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                reason_codes TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                final_action TEXT NOT NULL,
                classifier_source TEXT NOT NULL,
                processing_time_ms REAL NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_risk_level ON audit_logs(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs(request_id);")
        conn.commit()


@contextmanager
def get_db_connection():
    """Thread-safe context manager for sqlite connection."""
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
