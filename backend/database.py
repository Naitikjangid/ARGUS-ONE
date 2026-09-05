import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(__file__).resolve().with_name("argus_one.db")


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                bytes_out INTEGER NOT NULL,
                bytes_in INTEGER NOT NULL,
                packets_out INTEGER NOT NULL,
                packets_in INTEGER NOT NULL,
                tcp_flags TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_class TEXT NOT NULL,
                risk_score REAL NOT NULL,
                classification_confidence REAL NOT NULL,
                anomaly_confidence REAL NOT NULL,
                temporal_confidence REAL,
                payload TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_flows_timestamp
                ON flows(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp DESC);
            """
        )


def _timestamp(value: datetime | str) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def store_flow(flow: dict[str, Any]) -> None:
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO flows (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                bytes_out, bytes_in, packets_out, packets_in, tcp_flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _timestamp(flow["timestamp"]),
                flow["src_ip"],
                flow["dst_ip"],
                flow["src_port"],
                flow["dst_port"],
                flow["protocol"],
                flow["bytes_out"],
                flow["bytes_in"],
                flow["packets_out"],
                flow["packets_in"],
                flow["tcp_flags"],
            ),
        )


def store_alert(alert: dict[str, Any]) -> None:
    basis = alert.get("detection_basis", {}).get("behavioral_ml", {})
    with _connect() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO alerts (
                alert_id, timestamp, threat_class, risk_score,
                classification_confidence, anomaly_confidence,
                temporal_confidence, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["alert_id"],
                _timestamp(alert["timestamp"]),
                alert["threat_class"],
                alert["risk_score"],
                alert["classification_confidence"],
                alert["anomaly_confidence"],
                basis.get("temporal_confidence"),
                json.dumps(alert, separators=(",", ":")),
            ),
        )


def list_flows(limit: int = 100) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM flows ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_alerts(limit: int = 100) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT payload FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def get_alert(alert_id: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT payload FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    return json.loads(row["payload"]) if row else None


def statistics() -> dict[str, Any]:
    with _connect() as connection:
        total_flows = connection.execute(
            "SELECT COUNT(*) FROM flows"
        ).fetchone()[0]
        total_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]
        by_class = connection.execute(
            """
            SELECT threat_class, COUNT(*) AS count
            FROM alerts
            GROUP BY threat_class
            ORDER BY count DESC
            """
        ).fetchall()
        latest = connection.execute(
            "SELECT timestamp FROM alerts ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "alerts_by_threat_class": {
            row["threat_class"]: row["count"] for row in by_class
        },
        "latest_alert_timestamp": latest["timestamp"] if latest else None,
    }