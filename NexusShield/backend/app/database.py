from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.config import settings


def initialize_database(database_path: Path | None = None) -> None:
    path = database_path or settings.database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                content TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )"""
        )
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        }
        if "content" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN content TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('save_scan_content', 'false')"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                content TEXT NOT NULL,
                page_map TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )"""
        )
        document_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(documents)")
        }
        if "page_map" not in document_columns:
            connection.execute("ALTER TABLE documents ADD COLUMN page_map TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS security_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at)")


@contextmanager
def connect(database_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    path = database_path or settings.database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def get_save_scan_content() -> bool:
    with connect() as connection:
        row = connection.execute(
            "SELECT value FROM app_settings WHERE key = 'save_scan_content'"
        ).fetchone()
    return bool(row and row["value"] == "true")


def set_save_scan_content(enabled: bool) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO app_settings (key, value) VALUES ('save_scan_content', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("true" if enabled else "false",),
        )


def save_scan(
    scan_type: str, risk_score: int, verdict: str, content: str | None = None
) -> int:
    with connect() as connection:
        cursor = connection.execute(
            "INSERT INTO scans (scan_type, risk_score, verdict, content) VALUES (?, ?, ?, ?)",
            (scan_type, risk_score, verdict, content),
        )
        return int(cursor.lastrowid)
