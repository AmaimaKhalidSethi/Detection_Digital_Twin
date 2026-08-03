"""
Regression tests for the app.ai module fixes:

  1. rule_search platform filter must actually filter by the rule's own
     logsource.product, not just validate the query param.
  2. rule_search tactic filter must compare against MITRE tactic names
     (via technique -> tactic lookup), not raw technique IDs.
  3. alert_explainer / RuleMatcher must report which field(s)/value(s)
     actually caused a match, not a generic placeholder.
  4. technique_suggester's HTTP client must degrade to [] instead of
     raising when the provider call fails or returns something odd.
"""
from __future__ import annotations

import requests
from fastapi.testclient import TestClient

from app.ai.alert_explainer import explain_match
from app.ai.rule_search import search_rules
from app.ai.technique_suggester import _HttpClient
from app.detection_engine.matcher import RuleMatcher
from app.main import app
from app.models.db import Base, DetectionRule, RuleVersion, make_engine, make_session_factory


WINDOWS_RULE = """
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

LINUX_RULE = """
title: Suspicious Cron Job Creation
status: test
description: Detects creation of a new cron job entry
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'crontab -e'
    condition: selection
level: medium
tags:
    - attack.t1053.003
"""


def _session_factory(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'rule_search_fixture.db'}")
    Base.metadata.create_all(bind=engine)
    return make_session_factory(engine)


# --------------------------------------------------------------- platform --

def test_platform_filter_actually_filters_by_rule_platform(tmp_path):
    session_factory = _session_factory(tmp_path)
    with session_factory() as db:
        for yaml_content in (WINDOWS_RULE, LINUX_RULE):
            rule = DetectionRule(title="tmp", status="active")
            db.add(rule)
            db.flush()
            db.add(RuleVersion(rule_id=rule.id, version_number=1, yaml_content=yaml_content, mitre_techniques=[]))
        db.commit()

        windows_results = search_rules(db, "", platform="windows")
        linux_results = search_rules(db, "", platform="linux")

        assert {r["title"] for r in windows_results} == {"Suspicious Encoded PowerShell Command Line"}
        assert {r["title"] for r in linux_results} == {"Suspicious Cron Job Creation"}

        # A platform with no matching rules must exclude everything, not
        # pass everything through (the old bug: any *valid* platform name
        # matched every rule regardless of its actual logsource.product).
        assert search_rules(db, "", platform="macos") == []


def test_no_platform_filter_returns_everything(tmp_path):
    session_factory = _session_factory(tmp_path)
    with session_factory() as db:
        for yaml_content in (WINDOWS_RULE, LINUX_RULE):
            rule = DetectionRule(title="tmp", status="active")
            db.add(rule)
            db.flush()
            db.add(RuleVersion(rule_id=rule.id, version_number=1, yaml_content=yaml_content, mitre_techniques=[]))
        db.commit()

        assert len(search_rules(db, "")) == 2


# ----------------------------------------------------------------- tactic --

def test_tactic_filter_matches_by_tactic_name_not_technique_id(tmp_path):
    session_factory = _session_factory(tmp_path)
    with session_factory() as db:
        rule = DetectionRule(title="tmp", status="active")
        db.add(rule)
        db.flush()
        # T1003.001 -> tactic "Credential Access" per app/mitre/data.py
        db.add(RuleVersion(rule_id=rule.id, version_number=1, yaml_content=WINDOWS_RULE, mitre_techniques=["T1059.001", "T1003.001"]))
        db.commit()

        # This used to be impossible: the old code compared "credential
        # access" against ["T1059.001", "T1003.001"] and could never match.
        results = search_rules(db, "", tactic="credential access")
        assert len(results) == 1

        # A tactic this rule doesn't touch must exclude it.
        assert search_rules(db, "", tactic="persistence") == []


# -------------------------------------------------------- match explanation

def test_explanation_names_the_actual_matched_fields():
    explanation = explain_match(
        WINDOWS_RULE,
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -enc ABC"},
        None,
    )
    # Both AND-ed selections should show up, not a generic "condition" stub.
    assert "Image" in explanation
    assert "CommandLine" in explanation
    assert "condition" not in explanation.lower() or "field 'condition'" not in explanation


def test_explanation_reports_no_match_without_dumping_huge_payload():
    huge_event = {"Field": "x" * 2000}
    explanation = explain_match(WINDOWS_RULE, huge_event, None)
    assert "did not match" in explanation
    assert len(explanation) < 1000


def test_match_result_carries_evidence_for_or_condition():
    from sigma.rule import SigmaRule

    rule = SigmaRule.from_yaml(WINDOWS_RULE)
    matcher = RuleMatcher(rule)
    result = matcher.match({"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell -e ABC"})
    assert result.matched
    assert ("Image", "C:\\Windows\\System32\\powershell.exe") in result.matched_fields
    assert ("CommandLine", "powershell -e ABC") in result.matched_fields
    # Backward-compat single-field accessors still populated.
    assert result.matched_field is not None
    assert result.matched_value is not None


# ------------------------------------------------------- LLM failure paths

def test_http_client_returns_empty_list_on_connection_error(monkeypatch):
    client = _HttpClient("groq", "fake-key")

    def _raise(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr("requests.post", _raise)
    assert client.suggest_techniques("some rule text") == []


def test_http_client_returns_empty_list_on_http_error(monkeypatch):
    client = _HttpClient("openai", "fake-key")

    class _FakeResponse:
        def raise_for_status(self):
            raise requests.exceptions.HTTPError("500 server error")

        def json(self):
            return {}

    monkeypatch.setattr("requests.post", lambda *a, **k: _FakeResponse())
    assert client.suggest_techniques("some rule text") == []


def test_http_client_returns_empty_list_on_malformed_json_body(monkeypatch):
    client = _HttpClient("gemini", "fake-key")

    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr("requests.post", lambda *a, **k: _FakeResponse())
    assert client.suggest_techniques("some rule text") == []


def test_http_client_extracts_text_from_openai_response_with_reasoning_item_first(monkeypatch):
    """OpenAI's Responses API can put a reasoning item before the message
    item; the extractor must not assume output[0] is the message."""
    client = _HttpClient("openai", "fake-key")

    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "output": [
                    {"type": "reasoning", "summary": []},
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "T1059.001 and T1003.001"}],
                    },
                ]
            }

    monkeypatch.setattr("requests.post", lambda *a, **k: _FakeResponse())
    assert client.suggest_techniques("some rule text") == ["T1059.001", "T1003.001"]


def test_suggest_techniques_endpoint_survives_configured_provider_outage(monkeypatch):
    """End-to-end: a configured LLM provider that fails at the HTTP layer
    must not turn /rules/{id}/suggest-techniques into a 500 — the outage
    should be swallowed by _HttpClient and surface as zero suggestions."""
    client = TestClient(app)
    monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def _raise(*_args, **_kwargs):
        raise requests.exceptions.Timeout("simulated provider outage")

    monkeypatch.setattr("requests.post", _raise)

    rule_response = client.post("/rules", json={"yaml_content": WINDOWS_RULE})
    rule_id = rule_response.json()["rule_id"]

    response = client.post(f"/rules/{rule_id}/suggest-techniques")
    assert response.status_code == 200
    assert response.json()["suggestions"] == []