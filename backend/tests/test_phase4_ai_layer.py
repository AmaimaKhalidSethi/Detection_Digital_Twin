from fastapi.testclient import TestClient

from app.ai.technique_suggester import get_llm_client
from app.main import app


POWERSHELL_RULE = """
title: Suspicious Encoded PowerShell Command Line
status: test
description: Detects encoded PowerShell commands that read LSASS memory
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
tags:
    - attack.t1059.001
    - attack.t1003.001
"""


def test_rule_search_endpoint_returns_keyword_matches():
    client = TestClient(app)
    client.post("/rules", json={"yaml_content": POWERSHELL_RULE})

    response = client.get("/rules/search?q=lsass")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 1
    assert any("lsass" in item["title"].lower() or "lsass" in item["description"].lower() for item in payload)


def test_get_llm_client_supports_free_groq_keys(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    client = get_llm_client()

    assert client is not None
    assert client.provider == "groq"


def test_ai_suggested_rows_do_not_count_toward_coverage(monkeypatch):
    client = TestClient(app)

    class StubClient:
        def suggest_techniques(self, *_args, **_kwargs):
            return ["T1057"]

    monkeypatch.setattr("app.ai.technique_suggester.get_llm_client", lambda: StubClient())

    rule_response = client.post("/rules", json={"yaml_content": POWERSHELL_RULE})
    rule_id = rule_response.json()["rule_id"]

    suggestion_response = client.post(f"/rules/{rule_id}/suggest-techniques")
    assert suggestion_response.status_code == 200

    coverage = {row["technique_id"]: row for row in client.get("/coverage").json()}
    assert coverage["T1057"]["rule_passes"] is False
