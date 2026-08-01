from fastapi.testclient import TestClient

from app.main import SessionLocal, app


def _upload_rule(client, title, technique_id, detection_text):
    yaml = f"""
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
    response = client.post("/rules", json={"yaml_content": yaml})
    assert response.status_code == 200
    return response.json()


def test_full_matrix_job_writes_expected_bruteforce_rows_and_unexpected_matches(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr(
        "app.main.available_simulation_techniques",
        lambda: ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"],
    )

    rule1 = _upload_rule(client, "PowerShell rule", "T1059.001", "\\\\powershell.exe")
    rule2 = _upload_rule(client, "Tasklist rule", "T1057", ".exe")
    rule3 = _upload_rule(client, "Systeminfo rule", "T1082", ".exe")
    rule4 = _upload_rule(client, "Registry rule", "T1547.001", "reg.exe")
    rule5 = _upload_rule(client, "Scheduled task rule", "T1053.005", ".exe")

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
        expected = {
            (rule1["version_id"], "T1059.001"),
            (rule2["version_id"], "T1057"),
            (rule2["version_id"], "T1082"),
            (rule3["version_id"], "T1082"),
            (rule4["version_id"], "T1547.001"),
            (rule5["version_id"], "T1053.005"),
        }
        assert actual == expected
        assert all(row.confirmed for row in rows)
    finally:
        db.close()

    unexpected = client.post(f"/rules/{rule5['rule_id']}/test")
    assert unexpected.status_code == 200
    payload = unexpected.json()
    assert payload["rule_version_id"] == rule2["version_id"]
    assert payload["unexpected_matches"] == ["T1082"]
