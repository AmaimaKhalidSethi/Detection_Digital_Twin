from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.db import RuleTechniqueMap


def upsert_rule_technique_map(
    db: Session,
    rule_version_id: str,
    technique_id: str,
    source: str,
    confirmed: bool = True,
    confidence: float | None = None,
) -> None:
    row = (
        db.query(RuleTechniqueMap)
        .filter_by(rule_version_id=rule_version_id, technique_id=technique_id, source=source)
        .one_or_none()
    )
    if row is None:
        row = RuleTechniqueMap(
            rule_version_id=rule_version_id,
            technique_id=technique_id,
            source=source,
            confirmed=confirmed,
            confidence=confidence,
        )
        db.add(row)
        return
    row.confirmed = confirmed
    row.confidence = confidence
