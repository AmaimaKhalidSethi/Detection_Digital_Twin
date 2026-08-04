from types import SimpleNamespace

from fastapi.testclient import TestClient
from sigma.rule import SigmaRule

from app.detection_engine.matcher import RuleMatcher
from app.main import SessionLocal, app, _candidate_techniques_for_rule_version
from app.mitre.data import all_techniques
from app.telemetry.generators.synthetic_log_generator import run_simulation


def _build_rule_yaml(title, technique_id, detection_text):
    return f"""
title: {title}
status: test
description: test rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '{detection_text}'
    condition: selection
tags:
    - attack.execution
    - attack.{technique_id}
"""


def _upload_rule(client, title, technique_id, detection_text):
    yaml = _build_rule_yaml(title, technique_id, detection_text)
    response = client.post("/rules", json={"yaml_content": yaml})
    assert response.status_code == 200
    return response.json(), yaml


def test_candidate_techniques_for_rule_version_adds_all_sibling_techniques_for_declared_tactic():
    rule_version = SimpleNamespace(
        technique_mappings=[SimpleNamespace(technique_id="T1059.001", source="declared_tag")]
    )
    technique_meta = {
        "T1059.001": {"tactic": "execution"},
        "T1059.002": {"tactic": "execution"},
        "T1059.003": {"tactic": "execution"},
        "T1027": {"tactic": "defense_evasion"},
    }

    candidates = _candidate_techniques_for_rule_version(rule_version, technique_meta)

    assert candidates == ["T1059.001", "T1059.002", "T1059.003"]


def test_full_matrix_job_writes_expected_bruteforce_rows_and_unexpected_matches(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr(
        "app.main.available_simulation_techniques",
        lambda: ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"],
    )

    rule1, rule1_yaml = _upload_rule(client, "PowerShell rule", "T1059.001", "\\\\powershell.exe")
    rule2, rule2_yaml = _upload_rule(client, "Tasklist rule", "T1057", ".exe")
    rule3, rule3_yaml = _upload_rule(client, "Systeminfo rule", "T1082", ".exe")
    rule4, rule4_yaml = _upload_rule(client, "Registry rule", "T1547.001", "reg.exe")
    rule5, rule5_yaml = _upload_rule(client, "Scheduled task rule", "T1053.005", ".exe")

    job_response = client.post("/jobs/full-matrix-evaluation")
    assert job_response.status_code == 200
    job_id = job_response.json()["job_id"]

    job_status = client.get(f"/jobs/{job_id}")
    assert job_status.status_code == 200
    assert job_status.json()["status"] in {"done", "running"}

    db = SessionLocal()
    try:
        from app.models.db import RuleTechniqueMap

        rows = (
            db.query(RuleTechniqueMap)
            .filter(RuleTechniqueMap.source == "brute_force_confirmed")
            .all()
        )
        actual = {(row.rule_version_id, row.technique_id) for row in rows}
        expected = set()
        technique_meta = all_techniques()
        rule_versions = [
            (rule1, rule1_yaml, "T1059.001"),
            (rule2, rule2_yaml, "T1057"),
            (rule3, rule3_yaml, "T1082"),
            (rule4, rule4_yaml, "T1547.001"),
            (rule5, rule5_yaml, "T1053.005"),
        ]
        techniques = ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"]
        for payload, yaml_content, mapped_technique in rule_versions:
            rule_version = SimpleNamespace(
                technique_mappings=[SimpleNamespace(technique_id=mapped_technique, source="declared_tag")]
            )
            matcher = RuleMatcher(SigmaRule.from_yaml(yaml_content))
            for technique_id in techniques:
                event = run_simulation(technique_id, "expectation-check")[0]
                if matcher.match(event.to_dict()).matched:
                    expected.add((payload["version_id"], technique_id))
        print("ACTUAL:", sorted(actual))
        print("EXPECTED:", sorted(expected))
        print("EXTRA (in actual, not expected):", sorted(actual - expected))
        print("MISSING (in expected, not actual):", sorted(expected - actual))
        assert actual == expected
        assert all(row.confirmed for row in rows)
    finally:
        db.close()

    unexpected = client.post(f"/rules/{rule2['rule_id']}/test")
    assert unexpected.status_code == 200
    payload = unexpected.json()
    assert payload["rule_version_id"] == rule2["version_id"]
    assert payload["unexpected_matches"] == ["T1082"]


def test_full_matrix_job_evaluates_outside_declared_tactic_and_records_match(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr(
        "app.main.available_simulation_techniques",
        lambda: ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"],
    )

    rule, _ = _upload_rule(client, "Generic execution rule", "T1059.001", ".exe")
    job_response = client.post("/jobs/full-matrix-evaluation")
    assert job_response.status_code == 200

    job_id = job_response.json()["job_id"]
    job_status = client.get(f"/jobs/{job_id}")
    assert job_status.status_code == 200
    assert job_status.json()["status"] in {"done", "running"}

    db = SessionLocal()
    try:
        from app.models.db import RuleTechniqueMap

        rows = (
            db.query(RuleTechniqueMap)
            .filter(RuleTechniqueMap.source == "brute_force_confirmed")
            .filter(RuleTechniqueMap.rule_version_id == rule["version_id"])
            .all()
        )
        assert any(row.technique_id == "T1082" for row in rows)
    finally:
        db.close()


def test_rule_test_endpoint_reports_generic_exe_rule_as_unexpected_match_for_t1082(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr(
        "app.main.available_simulation_techniques",
        lambda: ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"],
    )

    rule2, _ = _upload_rule(client, "Tasklist rule", "T1057", ".exe")

    response = client.post(f"/rules/{rule2['rule_id']}/test")
    assert response.status_code == 200
    payload = response.json()
    assert "T1082" in payload["unexpected_matches"]
