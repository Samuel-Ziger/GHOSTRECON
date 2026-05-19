"""SQLite persistence — um JSON por projeto (bundle completo)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .schemas import ProjectBundle, ProjectSummary

DB_PATH = Path(__file__).resolve().parent.parent / "ghosttrace.db"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_bundles (
                id TEXT PRIMARY KEY,
                client TEXT NOT NULL,
                codename TEXT,
                status TEXT NOT NULL,
                engagement_type TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_projects() -> list[ProjectSummary]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, client, codename, status, engagement_type, updated_at, payload FROM project_bundles ORDER BY updated_at DESC"
        ).fetchall()
    out: list[ProjectSummary] = []
    for row in rows:
        payload = json.loads(row["payload"])
        vulns = payload.get("vulnerabilities") or []
        out.append(
            ProjectSummary(
                id=row["id"],
                client=row["client"],
                codename=row["codename"],
                status=row["status"],
                engagementType=row["engagement_type"],
                updatedAt=row["updated_at"],
                vulnerabilityCount=len(vulns),
            )
        )
    return out


def get_bundle(project_id: str) -> Optional[ProjectBundle]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT payload FROM project_bundles WHERE id = ?", (project_id,)
        ).fetchone()
    if not row:
        return None
    return ProjectBundle.model_validate(json.loads(row["payload"]))


def upsert_bundle(bundle: ProjectBundle) -> str:
    p = bundle.project
    ts = _now()
    p.updatedAt = ts
    payload = bundle.model_dump(mode="json")
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO project_bundles (id, client, codename, status, engagement_type, updated_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                client = excluded.client,
                codename = excluded.codename,
                status = excluded.status,
                engagement_type = excluded.engagement_type,
                updated_at = excluded.updated_at,
                payload = excluded.payload
            """,
            (
                p.id,
                p.client,
                p.codename,
                p.status,
                p.engagementType,
                ts,
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        conn.commit()
    return ts


def delete_project(project_id: str) -> bool:
    with _conn() as conn:
        cur = conn.execute("DELETE FROM project_bundles WHERE id = ?", (project_id,))
        conn.commit()
        return cur.rowcount > 0
