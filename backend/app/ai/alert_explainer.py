from __future__ import annotations

from sigma.rule import SigmaRule

from app.detection_engine.matcher import RuleMatcher

_MAX_EVENT_PREVIEW_CHARS = 500


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
        preview = str(event)
        if len(preview) > _MAX_EVENT_PREVIEW_CHARS:
            preview = preview[:_MAX_EVENT_PREVIEW_CHARS] + "... (truncated)"
        return f"The rule did not match event payload {preview}."

    evidence = getattr(match_result, "matched_fields", None) or []
    if not evidence:
        field = match_result.matched_field
        value = match_result.matched_value
        if field and value is not None:
            evidence = [(field, value)]

    if not evidence:
        return "The rule matched because its condition was satisfied, but no specific field could be identified (this can happen with negated or multi-condition rules)."

    if len(evidence) == 1:
        field, value = evidence[0]
        return f"The rule matched because field '{field}' matched value '{value}'."

    clauses = "; ".join(f"field '{f}' matched value '{v}'" for f, v in evidence)
    return f"The rule matched because all of the following were true: {clauses}."