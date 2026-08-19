from __future__ import annotations

import logging
import os
import re
from typing import Protocol

from dotenv import load_dotenv
from sigma.rule import SigmaRule

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))

from app.detection_engine.evaluator import evaluate_rule_version_against_events
from app.models.db import RuleTechniqueMap, RuleVersion
from app.telemetry.generators.synthetic_log_generator import run_simulation
from app.technique_maps import upsert_rule_technique_map, verify_and_upsert_confirmed_mapping

logger = logging.getLogger(__name__)

# Provider request/response wiring for each supported free-tier-friendly
# backend. Model IDs are the single most perishable part of this module —
# providers retire chat models on a matter of months, and a stale ID turns
# into a hard failure (404/400) rather than a degraded response. Verified
# current as of 2026-08:
#   - groq: llama-3.1-8b-instant was deprecated 2026-06-17 and is being
#     shut down 2026-08-16; openai/gpt-oss-20b is Groq's own recommended
#     replacement (console.groq.com/docs/deprecations).
#   - gemini: gemini-2.0-flash was fully shut down 2026-06-01; the
#     supported replacement is gemini-2.5-flash.
#   - openai: gpt-4o-mini's 4o-family is being wound down in favor of the
#     GPT-5 line; gpt-5-mini is the current cost-efficient, actively
#     supported model on the Responses API.
# If a provider retires its model again, only the constants below need to
# change.
_GROQ_MODEL = "openai/gpt-oss-20b"
_GEMINI_MODEL = "gemini-2.5-flash"
_OPENAI_MODEL = "gpt-5-mini"

_REQUEST_TIMEOUT_SECONDS = 20


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
        """Ask the configured provider for ATT&CK technique IDs.

        Never raises: any network failure, non-2xx response, or
        unexpected response shape is logged and treated as "no
        suggestions" so a flaky or misconfigured LLM provider degrades
        the /suggest-techniques endpoint instead of taking it down with
        a 500.
        """
        import requests

        prompt = (
            "Return only ATT&CK technique IDs like T1059.001, T1003.001, "
            f"or a JSON array of them for this rule: {rule_text}"
        )

        if self.provider == "groq":
            endpoint = "https://api.groq.com/openai/v1/chat/completions"
            payload = {
                "model": _GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            }
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        elif self.provider == "gemini":
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{_GEMINI_MODEL}:generateContent"
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            headers = {"x-goog-api-key": self.api_key}
        else:
            endpoint = "https://api.openai.com/v1/responses"
            payload = {"model": _OPENAI_MODEL, "input": prompt}
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=_REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as exc:
            logger.warning("LLM technique-suggestion request to %s failed: %s", self.provider, exc)
            return []
        except ValueError as exc:  # response body wasn't valid JSON
            logger.warning("LLM technique-suggestion response from %s was not valid JSON: %s", self.provider, exc)
            return []

        try:
            text = self._extract_text(data)
        except (AttributeError, IndexError, KeyError, TypeError) as exc:
            logger.warning("LLM technique-suggestion response from %s had an unexpected shape: %s", self.provider, exc)
            return []

        if not isinstance(text, str) or not text:
            return []
        return re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?", text)

    def _extract_text(self, data: dict) -> str:
        if self.provider == "gemini":
            candidates = data.get("candidates") or []
            if not candidates:
                return ""
            parts = candidates[0].get("content", {}).get("parts") or []
            return parts[0].get("text", "") if parts else ""

        if self.provider == "groq":
            choices = data.get("choices") or []
            if not choices:
                return ""
            return choices[0].get("message", {}).get("content", "")

        # OpenAI Responses API: the `output` array can contain reasoning,
        # tool-call, and message items in any order, so the assistant's
        # text is not reliably at output[0].content[0].text. Scan for the
        # message item(s) instead, per OpenAI's own guidance
        # (platform.openai.com/docs/guides/text).
        output = data.get("output") or []
        for item in output:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for block in item.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "output_text":
                    text = block.get("text", "")
                    if text:
                        return text
        return ""


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
            verify_and_upsert_confirmed_mapping(
                db,
                rule_version,
                technique_id,
                events[result["matched_event_index"]],
            )