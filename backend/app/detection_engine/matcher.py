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
from dataclasses import dataclass

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
    matched_field: str | None = None
    matched_value: str | None = None


def _leaf_matches(node, event: dict) -> bool:
    """Evaluate a single leaf condition node against the event."""
    value = node.value

    if isinstance(node, ConditionValueExpression):
        # Keyword-only detection (value must appear in *any* field) —
        # rare in practice but part of the Sigma spec.
        pattern = str(value)
        return any(
            fnmatch.fnmatch(str(v).lower(), pattern.lower())
            for v in event.values()
            if v is not None
        )

    field = node.field
    if field not in event:
        return False
    event_value = event[field]

    if isinstance(value, SigmaNumber):
        try:
            return int(event_value) == value.number
        except (TypeError, ValueError):
            return str(event_value) == str(value.number)

    if isinstance(value, SigmaString):
        pattern = str(value)  # pySigma already renders contains/endswith/
        # startswith modifiers as a glob pattern with '*' wildcards here.
        return fnmatch.fnmatch(str(event_value).lower(), pattern.lower())

    # Fallback: plain equality
    return str(event_value).lower() == str(value).lower()


def _eval_node(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval_node(child, event) for child in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_node(child, event) for child in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_node(node.args[0], event)
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        return _leaf_matches(node, event)
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
            if _eval_node(tree, event):
                return MatchResult(matched=True)
        return MatchResult(matched=False)

    def evaluate_batch(self, events: list[dict]) -> list[tuple[dict, MatchResult]]:
        return [(e, self.match(e)) for e in events]
