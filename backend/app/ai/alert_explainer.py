from __future__ import annotations

from sigma.rule import SigmaRule

from app.detection_engine.matcher import RuleMatcher


def explain_match(yaml_content: str, event: dict, match_result) -> str:
    try:
        rule = SigmaRule.from_yaml(yaml_content)
        matcher = RuleMatcher(rule)
    except Exception:
        return "The rule could not be parsed, so no structured explanation was available."

    # If caller didn't supply one, compute it.
    if match_result is None:
        match_result = matcher.match(event)

    if not match_result.matched:
        return f"The rule did not match event payload {event}."

    field = match_result.matched_field or "condition"
    value = match_result.matched_value
    
    if value is None:
        return f"The rule matched because its condition was satisfied by field '{field}'."
    return f"The rule matched because field '{field}' matched value '{value}'."
