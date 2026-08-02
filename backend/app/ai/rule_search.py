from __future__ import annotations

import os
import re
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.db import DetectionRule, RuleVersion


def ensure_rule_search_fts(db: Session) -> None:
    """Create a lightweight search table that works across SQLite versions."""
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS rule_search (
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                tags TEXT NOT NULL
            )
            """
        )
    )


def rebuild_rule_search_index(db: Session) -> None:
    """Populate the search table from the current rules."""
    db.execute(text("DELETE FROM rule_search"))
    rows = (
        db.query(DetectionRule.id, RuleVersion.id.label("version_id"), RuleVersion.yaml_content)
        .join(RuleVersion, RuleVersion.rule_id == DetectionRule.id)
        .all()
    )
    for rule_id, _version_id, yaml_content in rows:
        title = _extract_yaml_scalar(yaml_content, "title") or ""
        description = _extract_yaml_scalar(yaml_content, "description") or ""
        tags = _extract_yaml_tags(yaml_content)
        db.execute(
            text("INSERT INTO rule_search (rule_id, title, description, tags) VALUES (:rule_id, :title, :description, :tags)"),
            {"rule_id": rule_id, "title": title, "description": description, "tags": tags},
        )
    db.commit()


def search_rules(db: Session, query: str, tactic: Optional[str] = None, platform: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    ensure_rule_search_fts(db)
    rebuilt = False
    if not db.execute(text("SELECT 1 FROM rule_search LIMIT 1")).scalar():
        rebuild_rule_search_index(db)
        rebuilt = True

    tokens = [part for part in re.split(r"\s+", query.strip()) if part]
    if not tokens:
        tokens = [""]

    clauses = []
    params: dict[str, str] = {}
    for index, token in enumerate(tokens, start=1):
        key = f"term{index}"
        clauses.append(f"(title LIKE :{key} OR description LIKE :{key} OR tags LIKE :{key})")
        params[key] = f"%{token}%"

    sql = "SELECT rule_id, title, description, tags FROM rule_search"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    rows = db.execute(text(sql), params).fetchall()

    if not rows and not rebuilt:
        rebuild_rule_search_index(db)
        rows = db.execute(text(sql), params).fetchall()

    results = []
    for row in rows:
        rule = db.get(DetectionRule, row.rule_id)
        if not rule:
            continue
        latest = rule.latest_version
        if latest is None:
            continue
        if tactic and tactic.lower() not in (latest.mitre_techniques or []):
            continue
        if platform and platform.lower() not in ("windows", "linux", "macos"):
            continue
        if status and status.lower() != rule.status.lower():
            continue
        results.append(
            {
                "rule_id": rule.id,
                "title": latest.yaml_content and _extract_yaml_scalar(latest.yaml_content, "title") or rule.title,
                "description": _extract_yaml_scalar(latest.yaml_content, "description") or "",
                "tags": _extract_yaml_tags(latest.yaml_content),
                "status": rule.status,
                "version_number": latest.version_number,
            }
        )
    return results


def _extract_yaml_scalar(yaml_content: str, key: str) -> Optional[str]:
    pattern = rf"^{re.escape(key)}:\s*(.+)$"
    for line in yaml_content.splitlines():
        match = re.match(pattern, line.strip())
        if match:
            return match.group(1).strip().strip("\"'")
    return None


def _extract_yaml_tags(yaml_content: str) -> str:
    tags = []
    in_tags = False
    for line in yaml_content.splitlines():
        stripped = line.strip()
        if stripped.startswith("tags:"):
            in_tags = True
            continue
        if in_tags:
            if not stripped:
                continue
            if not line.startswith("    "):
                break
            tag = stripped.lstrip("-").strip()
            if tag:
                tags.append(tag)
    return " ".join(tags)
