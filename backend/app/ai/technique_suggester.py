from __future__ import annotations

import os
import re
from typing import Protocol

from dotenv import load_dotenv
from sigma.rule import SigmaRule

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))

from app.detection_engine.evaluator import evaluate_rule_version_against_events
from app.models.db import RuleTechniqueMap, RuleVersion
from app.telemetry.generators.synthetic_log_generator import run_simulation
from app.technique_maps import upsert_rule_technique_map


class LLMClient(Protocol):
    provider: str

    def suggest_techniques(self, rule_text: str) -> list[str]:
        ...


class _StubClient:
    provider = "none"

    def suggest_techniques(self, _rule_text: str) -> list[str]:
        return []


class _HttpClient:
    provider: str

    def __init__(self, provider: str, api_key: str) -> None:
        self.provider = provider
        self.api_key = api_key

    def suggest_techniques(self, rule_text: str) -> list[str]:
        import requests

        if self.provider == "groq":
            endpoint = "https://api.groq.com/openai/v1/chat/completions"
            payload = {
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": f"Return only ATT&CK technique IDs like T1059.001, T1003.001, or a JSON array of them for this rule: {rule_text}"}],
                "temperature": 0.1,
            }
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        elif self.provider == "gemini":
            endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
            payload = {"contents": [{"parts": [{"text": f"Return only ATT&CK technique IDs like T1059.001, T1003.001, or a JSON array of them for this rule: {rule_text}"}]}]}
            headers = {"x-goog-api-key": self.api_key}
        else:
            endpoint = "https://api.openai.com/v1/responses"
            payload = {"model": "gpt-4o-mini", "input": f"Return only ATT&CK technique IDs like T1059.001, T1003.001, or a JSON array of them for this rule: {rule_text}"}
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        if self.provider == "gemini":
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        elif self.provider == "groq":
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        else:
            text = data.get("output", [{}])[0].get("content", [{}])[0].get("text", "") if isinstance(data.get("output"), list) else ""

        if not isinstance(text, str):
            return []
        return re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?", text)


def get_llm_client() -> LLMClient | None:
    for provider, env_name in (("groq", "GROQ_API_KEY"), ("gemini", "GEMINI_API_KEY"), ("openai", "OPENAI_API_KEY")):
        api_key = os.getenv(env_name)
        if not api_key:
            continue
        return _HttpClient(provider, api_key)
    return _StubClient()


def _rule_to_plain_english(yaml_content: str) -> str:
    try:
        rule = SigmaRule.from_yaml(yaml_content)
    except Exception:
        return yaml_content
    return f"Rule {rule.title} targets {rule.detection.condition}."


def suggest_rule_techniques(rule_version: RuleVersion, db, yaml_content: str) -> list[str]:
    client = get_llm_client()
    if client is None:
        return []

    prompt = _rule_to_plain_english(yaml_content)
    suggested = [item for item in client.suggest_techniques(prompt) if re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", item)]
    for technique_id in suggested:
        upsert_rule_technique_map(db, rule_version.id, technique_id, "ai_suggested", confirmed=False)
    return suggested


def confirm_ai_suggestions(rule_version: RuleVersion, db, technique_ids: list[str]) -> None:
    for technique_id in technique_ids:
        if technique_id not in {row.technique_id for row in db.query(RuleTechniqueMap).filter(RuleTechniqueMap.rule_version_id == rule_version.id).all()}:
            continue
        events = run_simulation(technique_id, f"ai-confirm:{rule_version.id}:{technique_id}")
        result = evaluate_rule_version_against_events(rule_version.id, rule_version.yaml_content, events)
        if result["matched"]:
            upsert_rule_technique_map(db, rule_version.id, technique_id, "brute_force_confirmed", confirmed=True)
