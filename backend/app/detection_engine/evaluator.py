from __future__ import annotations

from sigma.rule import SigmaRule

from app.detection_engine.matcher import RuleMatcher


def evaluate_rule_version_against_events(
    rule_version_id: str,
    yaml_content: str,
    events: list[dict],
) -> dict:
    """Evaluate a single rule version against a batch of telemetry events."""
    try:
        rule = SigmaRule.from_yaml(yaml_content)
        matcher = RuleMatcher(rule)
    except Exception:
        return {"rule_version_id": rule_version_id, "matched": False, "matched_event_index": None}

    matched_index = None
    for i, event in enumerate(events):
        if matcher.match(event).matched:
            matched_index = i
            break
    return {
        "rule_version_id": rule_version_id,
        "matched": matched_index is not None,
        "matched_event_index": matched_index,
    }


def evaluate_rule_versions_against_events(
    rule_versions: list[tuple[str, str]],  # (rule_version_id, yaml_content)
    events: list[dict],
) -> list[dict]:
    """
    For every (rule_version_id, yaml) pair, evaluate against every event.
    Returns a list of {rule_version_id, matched, matched_event_index}.
    Rules that fail to parse are skipped (should not happen for stored
    rules, since they passed validate_rule_yaml on upload).
    """
    return [
        evaluate_rule_version_against_events(rule_version_id, yaml_content, events)
        for rule_version_id, yaml_content in rule_versions
    ]
