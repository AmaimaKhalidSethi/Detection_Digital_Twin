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


def _leaf_matches(node, event: dict) -> tuple[bool, str | None, str | None]:
    """Evaluate a single leaf condition node against the event.

    Returns (matched, field_name, matched_value) so the caller can build
    a human-readable explanation of what actually triggered the rule.
    """
    value = node.value

    if isinstance(node, ConditionValueExpression):
        # Keyword-only detection (value must appear in *any* field) —
        # rare in practice but part of the Sigma spec.
        pattern = str(value)
        for k, v in event.items():
            if v is not None and fnmatch.fnmatch(str(v).lower(), pattern.lower()):
                return True, k, str(v)
        return False, None, None

    field_name = node.field
    if field_name not in event:
        return False, None, None
    event_value = event[field_name]

    if isinstance(value, SigmaNumber):
        try:
            matched = int(event_value) == value.number
        except (TypeError, ValueError):
            matched = str(event_value) == str(value.number)
        return (matched, field_name, str(event_value)) if matched else (False, None, None)

    if isinstance(value, SigmaString):
        pattern = str(value)  # pySigma already renders contains/endswith/
        # startswith modifiers as a glob pattern with '*' wildcards here.
        matched = fnmatch.fnmatch(str(event_value).lower(), pattern.lower())
        return (matched, field_name, str(event_value)) if matched else (False, None, None)

    # Fallback: plain equality
    matched = str(event_value).lower() == str(value).lower()
    return (matched, field_name, str(event_value)) if matched else (False, None, None)


def _eval_node(node, event: dict) -> tuple[bool, list[tuple[str, str]]]:
    """Evaluate a condition node, returning (matched, evidence).

    `evidence` is the list of (field, value) leaves that made the match
    true — every satisfied leaf under an AND, or the satisfied branch's
    leaves under an OR.
    """
    if isinstance(node, ConditionAND):
        results = [_eval_node(child, event) for child in node.args]
        if not all(ok for ok, _ in results):
            return False, []
        evidence = [pair for _, pairs in results for pair in pairs]
        return True, evidence
    if isinstance(node, ConditionOR):
        for child in node.args:
            ok, evidence = _eval_node(child, event)
            if ok:
                return True, evidence
        return False, []
    if isinstance(node, ConditionNOT):
        ok, _ = _eval_node(node.args[0], event)
        # A negated condition being satisfied doesn't itself point to a
        # specific field/value that "caused" the match.
        return (not ok), []
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        ok, field_name, matched_value = _leaf_matches(node, event)
        if ok and field_name is not None:
            return True, [(field_name, matched_value)]
        return ok, []
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
        for tree in self._trees:
            matched, evidence = _eval_node(tree, event)
            if matched:
                first_field, first_value = evidence[0] if evidence else (None, None)
                return MatchResult(
                    matched=True,
                    matched_fields=evidence,
                    matched_field=first_field,
                    matched_value=first_value,
                )
        return MatchResult(matched=False)

    def evaluate_batch(self, events: list[dict]) -> list[tuple[dict, MatchResult]]:
        return [(e, self.match(e)) for e in events]