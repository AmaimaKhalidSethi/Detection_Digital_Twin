from __future__ import annotations

from sigma.rule import SigmaRule

from app.detection_engine.matcher import MatchResult, RuleMatcher


def _normalize_event(event) -> dict:
    if isinstance(event, dict):
        return event
    if hasattr(event, "to_dict"):
        return event.to_dict()
    if hasattr(event, "__dict__"):
        return {k: v for k, v in vars(event).items() if v is not None and k != "raw"}
    return dict(event)


def evaluate_rule_version_against_events(
    rule_version_id: str,
    yaml_content: str,
    events: list[dict],
) -> dict:
    """Evaluate a single rule version against a batch of telemetry events."""
    try:
        rule = SigmaRule.from_yaml(yaml_content)
        matcher = RuleMatcher(rule)
    except Exception as exc:
        return {
            "rule_version_id": rule_version_id,
            "matched": False,
            "matched_event_index": None,
            "parse_error": str(exc),
            "failure_reasons": [],
        }

    normalized_events = [_normalize_event(event) for event in events]
    matched_index = None
    failure_reasons: list[dict] = []
    for i, event in enumerate(normalized_events):
        result = matcher.match(event)
        if result.matched:
            matched_index = i
            break
        if not failure_reasons:
            failure_reasons = result.failure_reasons
    return {
        "rule_version_id": rule_version_id,
        "matched": matched_index is not None,
        "matched_event_index": matched_index,
        "parse_error": None,
        "failure_reasons": [] if matched_index is not None else failure_reasons,
    }


def evaluate_rule_versions_against_events(
    rule_versions: list[tuple[str, str]],  # (rule_version_id, yaml_content)
    events: list[dict],
) -> list[dict]:
    """
    For every (rule_version_id, yaml) pair, evaluate against every event.
    Returns a list of {rule_version_id, matched, matched_event_index, parse_error, failure_reasons}.
    Rules that fail to parse are skipped (should not happen for stored
    rules, since they passed validate_rule_yaml on upload).
    """
    return [
        evaluate_rule_version_against_events(rule_version_id, yaml_content, events)
        for rule_version_id, yaml_content in rule_versions
    ]
