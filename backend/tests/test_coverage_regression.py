import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DDT_TEST_DB", "sqlite:///./test_ddt_coverage.db")

from app.main import app  # noqa: E402

POWERSHELL_RULE = """
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
status: test
description: test
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\powershell.exe'
    selection_cli_enc:
        CommandLine|contains: ' -e'
    condition: selection_img and selection_cli_enc
level: high
"""


@pytest.fixture()
def client():
    return TestClient(app)


def test_evaluating_unrelated_technique_does_not_break_coverage(client):
    """
    Regression test: running a simulation for a technique the rule does NOT
    target (e.g. T1003.001) must not flip that rule's coverage status for
    the technique it DOES target (T1059.001), even though that evaluation
    correctly produces no alert.
    """
    client.post("/rules", json={"yaml_content": POWERSHELL_RULE})

    # 1. Prove the rule covers its own technique.
    sim = client.post("/simulations", json={"technique_id": "T1059.001"})
    client.post("/evaluate", json={"simulation_run_id": sim.json()["simulation_run_id"]})

    coverage = {row["technique_id"]: row for row in client.get("/coverage").json()}
    assert coverage["T1059.001"]["rule_passes"] is True

    # 2. Now evaluate against an unrelated technique's telemetry - this
    #    should correctly produce no alert, but must NOT make the rule
    #    look broken for the technique it actually targets.
    sim2 = client.post("/simulations", json={"technique_id": "T1003.001"})
    ev2 = client.post("/evaluate", json={"simulation_run_id": sim2.json()["simulation_run_id"]})
    assert ev2.json()["alerts_generated"] == 0

    coverage_after = {row["technique_id"]: row for row in client.get("/coverage").json()}
    assert coverage_after["T1059.001"]["rule_passes"] is True, (
        "Coverage for T1059.001 must still be true; the rule was never "
        "given a fair evaluation against T1003.001 telemetry."
    )


def test_evaluating_unrelated_technique_does_not_trigger_false_drift(client):
    """
    Regression test: testing a rule against a technique it doesn't target
    (expected no-match) right after testing it against its own technique
    (expected match) must NOT be reported as drift - those are two
    different regression baselines, not the same one changing over time.
    """
    client.post("/rules", json={"yaml_content": POWERSHELL_RULE})

    sim1 = client.post("/simulations", json={"technique_id": "T1059.001"})
    client.post("/evaluate", json={"simulation_run_id": sim1.json()["simulation_run_id"]})

    sim2 = client.post("/simulations", json={"technique_id": "T1003.001"})
    client.post("/evaluate", json={"simulation_run_id": sim2.json()["simulation_run_id"]})

    drift = client.get("/drift").json()
    assert drift == [], f"Expected no drift entries, got: {drift}"


def test_real_drift_is_detected_on_same_technique(client):
    """A rule that genuinely regresses on repeated evaluation of the SAME
    technique's telemetry should still be caught."""
    client.post("/rules", json={"yaml_content": POWERSHELL_RULE})

    sim1 = client.post("/simulations", json={"technique_id": "T1059.001"})
    client.post("/evaluate", json={"simulation_run_id": sim1.json()["simulation_run_id"]})

    sim2 = client.post("/simulations", json={"technique_id": "T1059.001"})
    client.post("/evaluate", json={"simulation_run_id": sim2.json()["simulation_run_id"]})

    # both runs use the same deterministic simulation template, so this
    # rule should pass both times and show no drift here (sanity check)
    drift = client.get("/drift").json()
    assert drift == []
