from app.models.db import (
    Base,
    DetectionRule,
    RuleTechniqueMap,
    RuleVersion,
    make_engine,
    make_session_factory,
)
from scripts.backfill_rule_technique_map import backfill_declared_technique_mappings


def test_backfill_creates_declared_mappings_and_is_idempotent(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'legacy_fixture.db'}")
    Base.metadata.create_all(bind=engine)
    session_factory = make_session_factory(engine)

    with session_factory() as db:
        rule = DetectionRule(title="Legacy rule")
        db.add(rule)
        db.flush()
        version_one = RuleVersion(
            rule_id=rule.id,
            version_number=1,
            yaml_content="title: legacy one",
            mitre_techniques=["T1059.001", "T1003.001", "T1059.001"],
        )
        version_two = RuleVersion(
            rule_id=rule.id,
            version_number=2,
            yaml_content="title: legacy two",
            mitre_techniques=["T1057"],
        )
        db.add_all([version_one, version_two])
        db.flush()
        # A confirmed result must not suppress the separate declared-tag row.
        db.add(
            RuleTechniqueMap(
                rule_version_id=version_one.id,
                technique_id="T1059.001",
                source="brute_force_confirmed",
                confirmed=True,
                confidence=1.0,
            )
        )
        db.commit()

        assert backfill_declared_technique_mappings(db) == 3
        db.commit()
        mappings = db.query(RuleTechniqueMap).all()
        assert {(m.technique_id, m.source, m.confirmed) for m in mappings} == {
            ("T1059.001", "declared_tag", False),
            ("T1059.001", "brute_force_confirmed", True),
            ("T1003.001", "declared_tag", False),
            ("T1057", "declared_tag", False),
        }

        assert backfill_declared_technique_mappings(db) == 0
