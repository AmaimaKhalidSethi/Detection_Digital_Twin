from fastapi.testclient import TestClient

from app.main import app, SessionLocal
from app.models.db import Endpoint, WazuhRule, WazuhRuleTechnique


client = TestClient(app)


def _create_environment():
    response = client.post(
        "/environments",
        json={
            "name": "Home Detection Lab",
            "description": "Prototype environment for the digital twin",
            "status": "active",
        },
    )
    assert response.status_code == 200
    return response.json()["id"]


def test_create_environment_and_record_sync_snapshot(monkeypatch):
    environment_id = _create_environment()

    class FakeWazuhClient:
        base_url = "http://wazuh.test"

        def get_manager_info(self):
            return {"data": {"version": "5.0.0"}}

        def get_agents(self):
            return [
                {
                    "id": "agent-001",
                    "name": "win-01",
                    "status": "active",
                    "os": {"name": "Windows", "version": "10"},
                    "version": "5.0.0",
                    "last_keepalive": "2026-08-08T10:00:00Z",
                },
                {
                    "id": "agent-002",
                    "hostname": "linux-01",
                    "status": "active",
                    "os": "Linux",
                    "version": "5.0.0",
                    "last_seen": "2026-08-08T09:45:00Z",
                },
            ]

        def get_rules(self):
            return [
                {
                    "rule_id": "100001",
                    "description": "Detect suspicious PowerShell activity",
                    "level": "12",
                    "status": "enabled",
                    "groups": ["windows", "powershell"],
                    "decoder": "json",
                    "mitre": ["T1059.001"],
                },
                {
                    "rule_id": "100002",
                    "description": "Detect suspicious process creation",
                    "level": "10",
                    "status": "disabled",
                    "groups": ["windows", "process"],
                    "decoder": "json",
                    "mitre": ["T1059.001", "T1003.001"],
                },
                {
                    "rule_id": "100003",
                    "description": "Detect suspicious network activity",
                    "level": "8",
                    "status": "enabled",
                    "groups": ["network"],
                    "decoder": "json",
                    "mitre": [],
                },
            ]

        def get_active_technique_ids(self):
            return {"T1059.001", "T1003.001"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    sync_response = client.post("/environment/sync")
    assert sync_response.status_code == 200
    payload = sync_response.json()
    assert payload["status"] == "ok"
    assert payload["agents_synced"] == 2
    assert payload["rules_synced"] == 3

    with SessionLocal() as db:
        agents = db.query(Endpoint).filter(Endpoint.agent_id.in_(["agent-001", "agent-002"])) .all()
        assert len(agents) == 2
        assert {agent.hostname for agent in agents} == {"win-01", "linux-01"}
        assert all(agent.agent_version == "5.0.0" for agent in agents)

        wazuh_rules = db.query(WazuhRule).all()
        assert len(wazuh_rules) == 3
        rule_map = {rule.rule_id: rule for rule in wazuh_rules}
        assert rule_map["100001"].status == "enabled"
        assert rule_map["100002"].status == "disabled"
        assert rule_map["100001"].groups == ["windows", "powershell"]

        technique_mappings = db.query(WazuhRuleTechnique).all()
        assert len(technique_mappings) == 3
        assert {mapping.technique_id for mapping in technique_mappings if mapping.wazuh_rule.rule_id == "100001"} == {"T1059.001"}

    snapshots_response = client.get("/environment/snapshots")
    assert snapshots_response.status_code == 200
    snapshots = snapshots_response.json()
    assert len(snapshots) >= 1
    assert snapshots[0]["environment_name"] == "Home Detection Lab"


def test_environment_sync_is_idempotent(monkeypatch):
    _create_environment()

    class FakeWazuhClient:
        base_url = "http://wazuh.test"

        def get_manager_info(self):
            return {"data": {"version": "5.0.0"}}

        def get_agents(self):
            return [
                {"id": "agent-001", "name": "win-01", "status": "active", "os": "Windows", "version": "5.0.0", "last_keepalive": "2026-08-08T10:00:00Z"},
            ]

        def get_rules(self):
            return [
                {"rule_id": "100001", "description": "Detect suspicious PowerShell activity", "level": "12", "status": "enabled", "groups": ["windows"], "decoder": "json", "mitre": ["T1059.001"]},
            ]

        def get_active_technique_ids(self):
            return {"T1059.001"}

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    client.post("/environment/sync")
    client.post("/environment/sync")

    with SessionLocal() as db:
        assert db.query(Endpoint).filter(Endpoint.agent_id == "agent-001").count() == 1
        assert db.query(WazuhRule).filter(WazuhRule.rule_id == "100001").count() == 1
        assert db.query(WazuhRuleTechnique).filter(WazuhRuleTechnique.technique_id == "T1059.001").count() == 1


def test_environment_sync_manager_unavailable(monkeypatch):
    _create_environment()

    class FakeWazuhClient:
        def get_manager_info(self):
            return None

        def get_agents(self):
            return []

        def get_rules(self):
            return []

        def get_active_technique_ids(self):
            return set()

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)

    response = client.post("/environment/sync")
    assert response.status_code == 503
    assert response.json()["detail"] == "Wazuh manager unavailable"

    with SessionLocal() as db:
        assert db.query(Endpoint).count() == 0
        assert db.query(WazuhRule).count() == 0


def test_configuration_drift_identifies_rule_status_and_content_changes(monkeypatch):
    _create_environment()
    state = {"status": "enabled", "description": "Original"}

    class FakeWazuhClient:
        base_url = "https://wazuh.test"
        def get_manager_info(self): return {"data": {"version": "5.0.0"}}
        def get_agents(self): return []
        def get_active_technique_ids(self): return {"T1059.001"}
        def get_rules(self):
            return [{"rule_id": "100001", "description": state["description"], "status": state["status"], "mitre": ["T1059.001"]}]

    monkeypatch.setattr("app.main.WazuhClient", FakeWazuhClient)
    assert client.post("/environment/sync").status_code == 200
    state.update(status="disabled", description="Updated")
    assert client.post("/environment/sync").status_code == 200
    changes = client.get("/drift/configuration").json()["changes"]
    assert changes[0]["category"] == "RULE_STATUS_CHANGED"
