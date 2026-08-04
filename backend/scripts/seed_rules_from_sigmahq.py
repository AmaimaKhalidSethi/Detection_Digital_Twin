"""Seed validated, attributed SigmaHQ rules from the vendored snapshot."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.detection_engine.matcher import RuleMatcher
from app.detection_engine.rule_manager import validate_rule_yaml
from app.models.db import (
    DetectionRule,
    RuleTechniqueMap,
    RuleVersion,
    init_db,
    make_engine,
    make_session_factory,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_ROOT = BACKEND_ROOT / "vendor" / "sigmahq" / "rules"
DEFAULT_REPORT_PATH = BACKEND_ROOT / "vendor" / "sigmahq" / "import_report.json"
SIGMAHQ_LICENSE = "DRL-1.1"
LOG = logging.getLogger(__name__)


def seed_sigmahq_rules(
    db: Session,
    rules_root: Path = DEFAULT_RULES_ROOT,
    report_path: Path | None = DEFAULT_REPORT_PATH,
) -> dict:
    """Validate, smoke-test, and persist every vendored SigmaHQ rule.

    Invalid rules and matcher-incompatible rules are retained in the report
    with a reason. No alternate parser or validator is used.
    """
    report = {"imported": 0, "skipped": 0, "skipped_reasons": []}
    for rule_path in sorted(rules_root.rglob("*.yml")):
        yaml_content = rule_path.read_text(encoding="utf-8")
        relative_path = str(rule_path.relative_to(rules_root)).replace("\\", "/")
        existing_version = db.query(RuleVersion).filter(RuleVersion.yaml_content == yaml_content).first()
        if existing_version:
            # Re-seeding repairs the confirmation state for already-imported
            # author-declared mappings as well as avoiding duplicate versions.
            (
                db.query(RuleTechniqueMap)
                .filter(RuleTechniqueMap.rule_version_id == existing_version.id)
                .filter(RuleTechniqueMap.source == "declared_tag")
                .update({RuleTechniqueMap.confirmed: True}, synchronize_session=False)
            )
            report["skipped"] += 1
            report["skipped_reasons"].append({"path": relative_path, "reason": "already imported"})
            continue

        result = validate_rule_yaml(yaml_content)
        if not result.valid or result.rule is None:
            report["skipped"] += 1
            reason = "; ".join(result.errors) or "validation failed"
            LOG.info("Skipping %s: %s", relative_path, reason)
            report["skipped_reasons"].append({"path": relative_path, "reason": reason})
            continue
        if not result.mitre_techniques:
            report["skipped"] += 1
            reason = "no MITRE ATT&CK technique tags"
            LOG.info("Skipping %s: %s", relative_path, reason)
            report["skipped_reasons"].append({"path": relative_path, "reason": reason})
            continue
        try:
            RuleMatcher(result.rule).match({})
        except Exception as error:
            report["skipped"] += 1
            reason = f"matcher smoke test: {error}"
            LOG.info("Skipping %s: %s", relative_path, reason)
            report["skipped_reasons"].append({"path": relative_path, "reason": reason})
            continue

        rule = DetectionRule(title=str(result.rule.title), status="active")
        db.add(rule)
        db.flush()
        version = RuleVersion(
            rule_id=rule.id,
            version_number=1,
            yaml_content=yaml_content,
            mitre_techniques=result.mitre_techniques or [],
            author=getattr(result.rule, "author", None),
            license=SIGMAHQ_LICENSE,
            source="sigma_import",
        )
        db.add(version)
        db.flush()
        for technique_id in dict.fromkeys(result.mitre_techniques or []):
            db.add(
                RuleTechniqueMap(
                    rule_version_id=version.id,
                    technique_id=technique_id,
                    source="declared_tag",
                    confirmed=True,
                )
            )
        report["imported"] += 1

    db.commit()
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-root", type=Path, default=DEFAULT_RULES_ROOT)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args()
    engine = make_engine()
    init_db(engine)
    session_factory = make_session_factory(engine)
    with session_factory() as db:
        report = seed_sigmahq_rules(db, args.rules_root, args.report_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
