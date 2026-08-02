import time

from fastapi.testclient import TestClient

import app.main as main


def test_debug_matrix_job(monkeypatch):
    client = TestClient(main.app)
    monkeypatch.setattr(
        main,
        "available_simulation_techniques",
        lambda: ["T1059.001", "T1057", "T1082", "T1547.001", "T1053.005"],
    )
    yaml = """
title: Debug
status: test
description: test rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
    condition: selection
tags:
    - attack.execution
    - attack.T1059.001
"""
    resp = client.post("/rules", json={"yaml_content": yaml})
    print("upload", resp.status_code, resp.json())
    job_resp = client.post("/jobs/full-matrix-evaluation")
    print("job create", job_resp.status_code, job_resp.json())

    job_id = job_resp.json()["job_id"]
    for _ in range(20):
        status = client.get(f"/jobs/{job_id}")
        print(status.json())
        if status.json()["status"] in {"done", "failed"}:
            break
        time.sleep(0.5)

    db = main.SessionLocal()
    try:
        from app.models.db import Job

        job = db.get(Job, job_id)
        print("stored job result_summary:", job.result_summary if job else None)
    finally:
        db.close()
