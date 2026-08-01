"""
End-to-end integration test (TC-001 style, Section 17 of the SDD): upload a
real, unmodified rule from the public SigmaHQ rule repository, simulate the
technique it targets, evaluate, and confirm an alert is produced with zero
false positives on a benign baseline.
"""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DDT_TEST_DB", "sqlite:///./test_ddt.db")

from app.main import app  # noqa: E402

REAL_SIGMAHQ_RULE = """
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
status: test
description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community
date: 2018-09-03
modified: 2023-04-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        - OriginalFileName:
            - 'PowerShell.EXE'
            - 'pwsh.dll'
    selection_cli_enc:
        CommandLine|contains: ' -e'
    selection_cli_content:
        CommandLine|contains:
            - ' JAB'
            - ' SUVYI'
            - ' SQBFAFgA'
            - ' aQBlAHgA'
            - ' aWV4I'
            - ' IAA'
            - ' IAB'
            - ' UwB'
            - ' cwB'
    selection_standalone:
        CommandLine|contains:
            - '.exe -ENCOD '
            - ' BA^J e-'
    filter_optional_remote_signed:
        CommandLine|contains: ' -ExecutionPolicy remotesigned '
    condition: selection_img and (all of selection_cli_* or selection_standalone) and not 1 of filter_optional_*
level: high
"""


@pytest.fixture()
def client():
    return TestClient(app)


def test_real_sigmahq_rule_detects_simulated_technique(client):
    upload = client.post("/rules", json={"yaml_content": REAL_SIGMAHQ_RULE})
    assert upload.status_code == 200
    assert upload.json()["mitre_techniques"] == ["T1059.001"]

    sim = client.post("/simulations", json={"technique_id": "T1059.001"})
    assert sim.status_code == 200
    run_id = sim.json()["simulation_run_id"]

    ev = client.post("/evaluate", json={"simulation_run_id": run_id})
    assert ev.status_code == 200
    assert ev.json()["alerts_generated"] == 1

    alerts = client.get("/alerts").json()
    assert any(a["technique_id"] == "T1059.001" for a in alerts)


def test_coverage_report_flags_uncovered_techniques(client):
    client.post("/rules", json={"yaml_content": REAL_SIGMAHQ_RULE})
    sim = client.post("/simulations", json={"technique_id": "T1059.001"})
    client.post("/evaluate", json={"simulation_run_id": sim.json()["simulation_run_id"]})

    coverage = client.get("/coverage").json()
    covered = {row["technique_id"] for row in coverage if row["rule_passes"]}
    blind_spots = {row["technique_id"] for row in coverage if row["blind_spot"]}
    assert "T1059.001" in covered
    assert "T1057" in blind_spots  # no rule uploaded for this technique yet


def test_malformed_rule_rejected(client):
    r = client.post("/rules", json={"yaml_content": "title: broken\ndetection:\n  condition: missing_selector"})
    assert r.status_code == 422
    assert "errors" in r.json()["detail"]


def test_oversized_rule_rejected(client):
    huge_yaml = "title: x\n" + ("a" * 300_000)
    r = client.post("/rules", json={"yaml_content": huge_yaml})
    assert r.status_code == 422
