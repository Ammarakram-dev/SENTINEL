import sqlite3
from pathlib import Path
from datetime import datetime


# Database location
DATABASE_PATH = Path(__file__).parent / "sentinel.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT NOT NULL,

            target_type TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            risk_level TEXT NOT NULL,

            recommendation TEXT,

            created_at TEXT NOT NULL

        )
    """)

    connection.commit()

    connection.close()


def save_scan(
    target,
    target_type,
    risk_score,
    risk_level,
    recommendation
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (
            target,
            target_type,
            risk_score,
            risk_level,
            recommendation,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        target,
        target_type,
        risk_score,
        risk_level,
        recommendation,
        datetime.now().isoformat(
            timespec="seconds"
        )
    ))

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return scan_id


def get_scan_history(limit=50):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            target,
            target_type,
            risk_score,
            risk_level,
            recommendation,
            created_at

        FROM scans

        ORDER BY id DESC

        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def get_scan(scan_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            target,
            target_type,
            risk_score,
            risk_level,
            recommendation,
            created_at

        FROM scans

        WHERE id = ?
    """, (scan_id,))

    row = cursor.fetchone()

    connection.close()

    if row:

        return dict(row)

    return None