from __future__ import annotations

import os
import re
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.mitre.data import get_technique
from app.models.db import DetectionRule, RuleVersion, RuleTechniqueMap


def ensure_rule_search_fts(db: Session) -> None:
    """Create a lightweight search table that works across SQLite versions."""
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS rule_search (
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                tags TEXT NOT NULL,
                platform TEXT NOT NULL DEFAULT ''
            )
            """
        )
    )
    # Idempotent compatibility migration: a table created before the
    # `platform` column existed won't get it from CREATE TABLE IF NOT
    # EXISTS, so add it explicitly if missing (same pattern as
    # app.models.db.init_db).
    columns = {row[1] for row in db.execute(text("PRAGMA table_info(rule_search)")).fetchall()}
    if "platform" not in columns:
        db.execute(text("ALTER TABLE rule_search ADD COLUMN platform TEXT NOT NULL DEFAULT ''"))
        db.commit()


def rebuild_rule_search_index(db: Session) -> None:
    """Populate the search table from the current rules."""
    ensure_rule_search_fts(db)
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
        platform = _extract_yaml_logsource_product(yaml_content) or ""
        db.execute(
            text(
                "INSERT INTO rule_search (rule_id, title, description, tags, platform) "
                "VALUES (:rule_id, :title, :description, :tags, :platform)"
            ),
            {"rule_id": rule_id, "title": title, "description": description, "tags": tags, "platform": platform},
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

    sql = "SELECT rule_id, title, description, tags, platform FROM rule_search"
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
        mitre_techniques = sorted({mapping.technique_id for mapping in latest.technique_mappings})
        if tactic:
            # Technique IDs on the rule (e.g. "T1003.001") each map to a
            # MITRE tactic (e.g. "Credential Access") via the local
            # technique table; compare against *that*, not the raw
            # technique IDs, which is what "tactic" actually means here.
            rule_tactics = {
                (get_technique(tid) or {}).get("tactic", "").lower()
                for tid in (latest.mitre_techniques or [])
            }
            if tactic.lower() not in rule_tactics:
                continue
        if platform:
            # `row.platform` is the rule's own logsource.product, parsed
            # out of its YAML at index time — not a validity check on the
            # query param, which is what this used to (incorrectly) do.
            if (row.platform or "").lower() != platform.lower():
                continue
        if status is None:
            if rule.status.lower() == "archived":
                continue
        elif status.lower() == "archived":
            if rule.status.lower() != "archived":
                continue
        elif status.lower() != rule.status.lower():
            continue
        results.append(
            {
                "rule_id": rule.id,
                "title": latest.yaml_content and _extract_yaml_scalar(latest.yaml_content, "title") or rule.title,
                "description": _extract_yaml_scalar(latest.yaml_content, "description") or "",
                "tags": _extract_yaml_tags(latest.yaml_content),
                "platform": row.platform or None,
                "status": rule.status,
                "version_number": latest.version_number,
                "mitre_techniques": mitre_techniques,
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


def _extract_yaml_logsource_product(yaml_content: str) -> Optional[str]:
    """Pull `logsource.product` (e.g. 'windows', 'linux') out of rule YAML.

    Uses the same lightweight line-scanning approach as the other
    extractors here rather than a full YAML parse, since this module
    already commits to that tradeoff for title/description/tags.
    """
    in_logsource = False
    for line in yaml_content.splitlines():
        stripped = line.strip()
        if stripped.startswith("logsource:"):
            in_logsource = True
            continue
        if in_logsource:
            if not stripped:
                continue
            if not line[:1].isspace():
                break
            if stripped.startswith("product:"):
                return stripped.split(":", 1)[1].strip().strip("\"'") or None
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