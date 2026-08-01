import json

from fastapi.testclient import TestClient
from sigma.rule import SigmaRule
import yaml

from app.detection_engine.matcher import RuleMatcher
from app.main import app
from app.models.db import (
    Base,
    DetectionRule,
    DetectionResult,
    RuleTechniqueMap,
    RuleVersion,
    SimulationRun,
    make_engine,
    make_session_factory,
)
from scripts.seed_rules_from_sigmahq import SIGMAHQ_LICENSE, seed_sigmahq_rules


def test_seeded_sigmahq_rules_are_validated_mapped_and_matcher_safe(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'sigmahq_seed.db'}")
    Base.metadata.create_all(bind=engine)
    session_factory = make_session_factory(engine)
    report_path = tmp_path / "import_report.json"
    try:
        with session_factory() as db:
            report = seed_sigmahq_rules(db, report_path=report_path)
            imported = db.query(RuleVersion).all()

            assert 200 <= report["imported"] <= 300
            assert report["imported"] == len(imported)
            assert json.loads(report_path.read_text(encoding="utf-8")) == report
            assert report["skipped"] == len(report["skipped_reasons"])

            for version in imported:
                assert version.license == SIGMAHQ_LICENSE
                assert db.query(RuleTechniqueMap).filter_by(rule_version_id=version.id).count() >= 1
                source_author = (yaml.safe_load(version.yaml_content) or {}).get("author")
                assert version.author == source_author
                RuleMatcher(SigmaRule.from_yaml(version.yaml_content)).match({})
    finally:
        engine.dispose()


AUTHORED_RULE = """
title: Alert Attribution Test
id: 00000000-0000-4000-8000-000000000010
status: test
author: Detection Engineering Team
license: LicenseRef-Internal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
tags:
  - attack.t1059.001
level: low
"""


def test_alerts_include_the_rule_author():
    client = TestClient(app)
    uploaded = client.post("/rules", json={"yaml_content": AUTHORED_RULE})
    assert uploaded.status_code == 200

    simulation = client.post("/simulations", json={"technique_id": "T1059.001"})
    assert simulation.status_code == 200
    client.post("/evaluate", json={"simulation_run_id": simulation.json()["simulation_run_id"]})

    alerts = client.get("/alerts").json()
    assert any(alert["rule_author"] == "Detection Engineering Team" for alert in alerts)
