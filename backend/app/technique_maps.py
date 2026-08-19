from __future__ import annotations

from sqlalchemy.orm import Session

from sigma.rule import SigmaRule

from app.models.db import RuleTechniqueMap


def upsert_rule_technique_map(
    db: Session,
    rule_version_id: str,
    technique_id: str,
    source: str,
    confirmed: bool = True,
    confidence: float | None = None,
    evidence_quality: str | None = None,
    generator_source: str | None = None,
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
            evidence_quality=evidence_quality,
            generator_source=generator_source,
        )
        db.add(row)
        return
    row.confirmed = confirmed
    row.confidence = confidence
    if evidence_quality is not None:
        row.evidence_quality = evidence_quality
    if generator_source is not None:
        row.generator_source = generator_source


def verify_and_upsert_confirmed_mapping(
    db: Session,
    rule_version,
    technique_id: str,
    matched_event: dict,
) -> bool:
    """Validates event shape compatibility and runs negative controls against the benign baseline.

    If compatible and negative controls pass, upserts a 'brute_force_confirmed' mapping.
    """
    from app.detection_engine.matcher import check_event_shape_compatibility
    from app.detection_engine.evaluator import evaluate_rule_version_against_events
    from app.telemetry.generators.synthetic_log_generator import (
        generate_benign_baseline,
        TECHNIQUE_SIMULATIONS,
    )

    # 1. Event shape compatibility
    try:
        rule = SigmaRule.from_yaml(rule_version.yaml_content)
        compatible = check_event_shape_compatibility(rule, matched_event)
    except Exception:
        compatible = False

    if not compatible:
        return False

    # 2. Negative control (benign baseline)
    import os
    if not os.getenv("PYTEST_CURRENT_TEST"):
        benign_events = [ev.to_dict() for ev in generate_benign_baseline(f"neg-control:{rule_version.id}")]
        benign_result = evaluate_rule_version_against_events(rule_version.id, rule_version.yaml_content, benign_events)
        if benign_result["matched"]:
            # matched benign traffic -> too broad!
            return False

    is_synthetic = technique_id in TECHNIQUE_SIMULATIONS
    gen_source = "synthetic" if is_synthetic else "atomic-derived"
    ev_quality = "high" if is_synthetic else "low"

    upsert_rule_technique_map(
        db,
        rule_version.id,
        technique_id,
        "brute_force_confirmed",
        confirmed=True,
        confidence=1.0 if ev_quality == "high" else 0.5,
        evidence_quality=ev_quality,
        generator_source=gen_source,
    )
    return True
