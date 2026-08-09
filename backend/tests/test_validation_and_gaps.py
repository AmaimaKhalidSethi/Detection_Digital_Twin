from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _create_environment_and_endpoint():
    environment_response = client.post(
        "/environments",
        json={"name": "Validation Lab", "description": "Twin validation workspace", "status": "active"},
    )
    assert environment_response.status_code == 200
    environment_id = environment_response.json()["id"]

    endpoint_response = client.post(
        f"/environments/{environment_id}/endpoints",
        json={"hostname": "win-01", "operating_system": "windows", "agent_id": "agent-01", "agent_status": "active"},
    )
    assert endpoint_response.status_code == 200
    endpoint_id = endpoint_response.json()["id"]
    return environment_id, endpoint_id


def test_validation_run_uses_wazuh_detection(monkeypatch):
    environment_id, endpoint_id = _create_environment_and_endpoint()

    class FakeWazuhClient:
        def run_logtest(self, log_input):
            return {"matched": True, "rule_id": "rule-123", "message": "matched"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post(
        "/validation-runs",
        json={
            "environment_id": environment_id,
            "endpoint_id": endpoint_id,
            "technique_id": "T1059.001",
            "simulation_id": "sim-001",
            "expected_detection": "DETECT",
            "telemetry": "powershell -enc aGVsbG8=",
            "observed_detection": "DETECT",
            "status": "VALIDATED",
            "evidence": {"method": "simulated"},
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_detection"] == "DETECT"
    assert payload["status"] == "VALIDATED"
    assert payload["validation_source"] == "WAZUH_LOGTEST"

    gap_response = client.get(f"/detection-gaps?environment_id={environment_id}")
    assert gap_response.status_code == 200
    assert gap_response.json() == []


def test_validation_run_creates_gap_when_wazuh_fails_to_detect(monkeypatch):
    environment_id, endpoint_id = _create_environment_and_endpoint()

    class FakeWazuhClient:
        def run_logtest(self, log_input):
            return {"matched": False, "rule_id": None, "message": "no match"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post(
        "/validation-runs",
        json={
            "environment_id": environment_id,
            "endpoint_id": endpoint_id,
            "technique_id": "T1059.001",
            "expected_detection": "DETECT",
            "telemetry": "echo test",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_detection"] == "NO_DETECT"
    assert payload["status"] == "DETECTION_GAP"

    gap_response = client.get(f"/detection-gaps?environment_id={environment_id}")
    assert gap_response.status_code == 200
    gaps = gap_response.json()
    assert len(gaps) == 1
    assert gaps[0]["technique_id"] == "T1059.001"


def test_validation_run_skips_gap_for_expected_no_detection(monkeypatch):
    environment_id, endpoint_id = _create_environment_and_endpoint()

    class FakeWazuhClient:
        def run_logtest(self, log_input):
            return {"matched": False, "rule_id": None, "message": "no match"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post(
        "/validation-runs",
        json={
            "environment_id": environment_id,
            "endpoint_id": endpoint_id,
            "technique_id": "T1059.001",
            "expected_detection": "NO_DETECT",
            "telemetry": "echo harmless",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_detection"] == "NO_DETECT"
    assert payload["status"] == "VALIDATED"

    gap_response = client.get(f"/detection-gaps?environment_id={environment_id}")
    assert gap_response.status_code == 200
    assert gap_response.json() == []


def test_validation_run_marks_unavailable_when_wazuh_fails(monkeypatch):
    environment_id, endpoint_id = _create_environment_and_endpoint()

    class FakeWazuhClient:
        def run_logtest(self, log_input):
            raise RuntimeError("timeout")

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post(
        "/validation-runs",
        json={
            "environment_id": environment_id,
            "endpoint_id": endpoint_id,
            "technique_id": "T1059.001",
            "expected_detection": "DETECT",
            "telemetry": "echo test",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_detection"] is None
    assert payload["status"] == "UNAVAILABLE"

    gap_response = client.get(f"/detection-gaps?environment_id={environment_id}")
    assert gap_response.status_code == 200
    assert gap_response.json() == []


def test_validation_run_ignores_caller_forged_result(monkeypatch):
    environment_id, endpoint_id = _create_environment_and_endpoint()

    class FakeWazuhClient:
        def run_logtest(self, log_input):
            return {"matched": False, "rule_id": None, "message": "no match"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post(
        "/validation-runs",
        json={
            "environment_id": environment_id,
            "endpoint_id": endpoint_id,
            "technique_id": "T1059.001",
            "expected_detection": "DETECT",
            "telemetry": "echo test",
            "observed_detection": "DETECT",
            "status": "VALIDATED",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_detection"] == "NO_DETECT"
    assert payload["status"] == "DETECTION_GAP"
