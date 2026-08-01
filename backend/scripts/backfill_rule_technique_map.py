"""One-time backfill of normalized declared technique mappings.

Run from the ``backend`` directory after deploying the schema change:

    python scripts/backfill_rule_technique_map.py

The legacy ``RuleVersion.mitre_techniques`` JSON field is read only here.
All application queries use ``rule_technique_map`` instead.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.db import (
    RuleTechniqueMap,
    RuleVersion,
    init_db,
    make_engine,
    make_session_factory,
)


def backfill_declared_technique_mappings(db: Session) -> int:
    """Create missing ``declared_tag`` mappings from the legacy JSON field.

    The operation is idempotent; existing declared mappings are also upgraded
    to confirmed because the rule author supplied their ATT&CK tag.
    """
    added = 0
    for version in db.query(RuleVersion).yield_per(100):
        technique_ids = version.mitre_techniques or []
        for technique_id in set(technique_ids):
            key = (version.id, technique_id, "declared_tag")
            existing = db.get(RuleTechniqueMap, key)
            if existing is not None:
                existing.confirmed = True
                continue
            db.add(
                RuleTechniqueMap(
                    rule_version_id=version.id,
                    technique_id=technique_id,
                    source="declared_tag",
                    confirmed=True,
                )
            )
            added += 1
    return added


def main() -> None:
    engine = make_engine()
    init_db(engine)
    session_factory = make_session_factory(engine)
    with session_factory() as db:
        added = backfill_declared_technique_mappings(db)
        db.commit()
    print(f"Backfilled {added} declared technique mappings.")


if __name__ == "__main__":
    main()
