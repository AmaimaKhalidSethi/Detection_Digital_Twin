"""
Detection engine core.

pySigma (SigmaHQ/pySigma) is a *parsing and conversion* library: it parses
Sigma YAML into an object model and converts that model into queries for a
target backend (Splunk, Elastic, etc. via separate backend packages). It
does not ship a backend that evaluates a rule directly against a Python
event dict.

This module is that missing piece: a small, direct evaluator that walks
pySigma's own parsed condition tree (`SigmaRule.detection.parsed_condition`)
and checks it against a normalized event dict in memory. This keeps us on
pySigma's real parser/object model (so any valid Sigma rule from SigmaHQ's
public rule repository parses correctly) while avoiding a full custom
Sigma grammar implementation.

Grounded in pySigma's actual object model (verified interactively against
pysigma==1.4.0):
  - rule.detection.parsed_condition -> list[SigmaCondition]
  - SigmaCondition.parsed -> a tree of ConditionAND / ConditionOR /
    ConditionNOT (each with `.args`) with ConditionFieldEqualsValueExpression
    or ConditionValueExpression leaves (each with `.field` (or None for
    keyword-only) and `.value`).
  - Leaf `.value` is a SigmaString (wildcard modifiers like `contains` /
    `endswith` / `startswith` are already folded into the string as glob
    `*` characters by the parser) or a SigmaNumber (has `.number`).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from sigma.conditions import (
    ConditionAND,
    ConditionNOT,
    ConditionOR,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaNumber, SigmaString

FailureReason = dict[str, str | None]


@dataclass
class MatchResult:
    matched: bool
    # Every (field, value) leaf that contributed to the match, so callers
    # (e.g. the alert explainer) can say *why* a rule fired, not just that
    # it did. matched_field/matched_value are kept as convenience aliases
    # for the first piece of evidence.
    matched_fields: list[tuple[str, str]] = field(default_factory=list)
    matched_field: str | None = None
    matched_value: str | None = None
    # When a rule does not match, these describe why it failed. For AND
    # combinations the first failing leaf is returned; for OR combinations all
    # failing leaves are returned so callers can see why no branch succeeded.
    failure_reasons: list[FailureReason] = field(default_factory=list)


def _make_failure_reason(field_name: str, reason: str, expected: str, actual: str | None) -> FailureReason:
    return {
        "field": field_name,
        "reason": reason,
        "expected": expected,
        "actual": actual,
    }


def _leaf_matches(
    node,
    event: dict,
) -> tuple[bool, str | None, str | None, FailureReason | None]:
    """Evaluate a single leaf condition node against the event.

    Returns (matched, field_name, matched_value, failure_reason) for the
    caller to build a human-readable explanation of both why the rule fired
    and why it failed.
    """
    value = node.value

    if isinstance(node, ConditionValueExpression):
        # Keyword-only detection (value must appear in *any* field) —
        # rare in practice but part of the Sigma spec.
        pattern = str(value)
        for k, v in event.items():
            if v is not None and fnmatch.fnmatch(str(v).lower(), pattern.lower()):
                return True, k, str(v), None
        return False, "<any>", None, _make_failure_reason(
            "<any>", "value_mismatch", pattern, None
        )

    field_name = node.field
    if field_name not in event:
        return (
            False,
            field_name,
            None,
            _make_failure_reason(field_name, "field_missing", str(value), None),
        )
    event_value = event[field_name]

    if isinstance(value, SigmaNumber):
        try:
            matched = int(event_value) == value.number
        except (TypeError, ValueError):
            matched = str(event_value) == str(value.number)
        if matched:
            return True, field_name, str(event_value), None
        return (
            False,
            field_name,
            None,
            _make_failure_reason(field_name, "value_mismatch", str(value.number), str(event_value)),
        )

    if isinstance(value, SigmaString):
        pattern = str(value)  # pySigma already renders contains/endswith/
        # startswith modifiers as a glob pattern with '*' wildcards here.
        matched = fnmatch.fnmatch(str(event_value).lower(), pattern.lower())
        if matched:
            return True, field_name, str(event_value), None
        return (
            False,
            field_name,
            None,
            _make_failure_reason(field_name, "value_mismatch", pattern, str(event_value)),
        )

    # Fallback: plain equality
    matched = str(event_value).lower() == str(value).lower()
    if matched:
        return True, field_name, str(event_value), None
    return (
        False,
        field_name,
        None,
        _make_failure_reason(field_name, "value_mismatch", str(value), str(event_value)),
    )


def _eval_node(
    node,
    event: dict,
) -> tuple[bool, list[tuple[str, str]], list[FailureReason]]:
    """Evaluate a condition node, returning (matched, evidence, failure_reasons).

    `evidence` is the list of (field, value) leaves that made the match
    true — every satisfied leaf under an AND, or the satisfied branch's
    leaves under an OR.

    `failure_reasons` is populated only when the node does not match. For an
    AND the first failing leaf's reason is returned; for an OR all failing
    leaf reasons are returned.
    """
    if isinstance(node, ConditionAND):
        results = [_eval_node(child, event) for child in node.args]
        for ok, _, reasons in results:
            if not ok:
                return False, [], reasons[:1] if reasons else []
        evidence = [pair for _, pairs, _ in results for pair in pairs]
        return True, evidence, []
    if isinstance(node, ConditionOR):
        failure_reasons: list[FailureReason] = []
        for child in node.args:
            ok, evidence, reasons = _eval_node(child, event)
            if ok:
                return True, evidence, []
            failure_reasons.extend(reasons)
        return False, [], failure_reasons
    if isinstance(node, ConditionNOT):
        ok, _, _ = _eval_node(node.args[0], event)
        # A negated condition being satisfied doesn't itself point to a
        # specific field/value that "caused" the match.
        return (not ok), [], []
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        ok, field_name, matched_value, failure_reason = _leaf_matches(node, event)
        if ok and field_name is not None:
            return True, [(field_name, matched_value)], []
        return False, [], [failure_reason] if failure_reason else []
    raise TypeError(f"Unsupported condition node type: {type(node)}")


class RuleMatcher:
    """Evaluates one parsed SigmaRule against normalized events."""

    def __init__(self, rule: SigmaRule):
        self.rule = rule
        if not rule.detection.parsed_condition:
            raise ValueError(f"Rule '{rule.title}' has no parsable condition")
        # A rule can define multiple conditions (rare); treat as OR of all.
        self._trees = [c.parsed for c in rule.detection.parsed_condition]

    def match(self, event: dict) -> MatchResult:
        failure_reasons: list[FailureReason] = []
        for tree in self._trees:
            matched, evidence, reasons = _eval_node(tree, event)
            if matched:
                first_field, first_value = evidence[0] if evidence else (None, None)
                return MatchResult(
                    matched=True,
                    matched_fields=evidence,
                    matched_field=first_field,
                    matched_value=first_value,
                )
            failure_reasons.extend(reasons)
        return MatchResult(matched=False, failure_reasons=failure_reasons)

    def evaluate_batch(self, events: list[dict]) -> list[tuple[dict, MatchResult]]:
        return [(e, self.match(e)) for e in events]


def check_event_shape_compatibility(rule: SigmaRule, event: dict) -> bool:
    """Ensure the event fields are compatible with the rule's logsource category."""
    category = getattr(rule.logsource, "category", None)
    if not category:
        return True
    category = str(category).strip().lower()
    if category == "network_connection":
        return "DestinationIp" in event or "DestinationPort" in event
    elif category == "registry_event":
        return "TargetObject" in event or "Details" in event
    elif category == "process_creation":
        return "Image" in event or "CommandLine" in event
    return True


