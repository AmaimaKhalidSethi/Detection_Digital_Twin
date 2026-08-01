"""
Sigma rule upload / validation / versioning (FR-01, FR-02, FR-03).

Uses pySigma's real SigmaRule.from_yaml parser for validation, so any rule
that would be rejected here would also be rejected by any other pySigma-
based tool (SigmaHQ's own CI, sigma-cli, etc).
"""
from __future__ import annotations

from dataclasses import dataclass

import yaml
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError

SUPPORTED_LOGSOURCE_PRODUCTS = {"windows", "linux"}
SUPPORTED_LOGSOURCE_CATEGORIES = {"process_creation", "registry_event", "network_connection"}
MAX_RULE_YAML_BYTES = 200_000  # guards against oversized/malformed uploads (NFR, Section 6)


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]
    rule: SigmaRule | None = None
    mitre_techniques: list[str] | None = None


def extract_mitre_techniques(rule: SigmaRule) -> list[str]:
    ids = []
    for tag in rule.tags or []:
        # pySigma tags look like SigmaRuleTag(namespace='attack', name='t1059.001')
        name = tag.name if hasattr(tag, "name") else str(tag)
        if name.lower().startswith("t") and name[1:2].isdigit():
            ids.append(name.upper())
    return ids


def validate_rule_yaml(yaml_text: str) -> ValidationResult:
    if len(yaml_text.encode("utf-8")) > MAX_RULE_YAML_BYTES:
        return ValidationResult(valid=False, errors=[f"Rule exceeds {MAX_RULE_YAML_BYTES} byte limit"])

    try:
        # Fail fast on malformed YAML before handing to pySigma
        yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return ValidationResult(valid=False, errors=[f"Invalid YAML: {e}"])

    try:
        rule = SigmaRule.from_yaml(yaml_text)
    except SigmaError as e:
        return ValidationResult(valid=False, errors=[f"Sigma validation error: {e}"])
    except Exception as e:  # pySigma raises plain pydantic ValidationError too
        return ValidationResult(valid=False, errors=[f"Rule parsing failed: {e}"])

    errors = []
    product = rule.logsource.product
    category = rule.logsource.category
    if product and product not in SUPPORTED_LOGSOURCE_PRODUCTS:
        errors.append(f"Unsupported logsource.product '{product}' (supported: {sorted(SUPPORTED_LOGSOURCE_PRODUCTS)})")
    if category and category not in SUPPORTED_LOGSOURCE_CATEGORIES:
        errors.append(f"Unsupported logsource.category '{category}' (supported: {sorted(SUPPORTED_LOGSOURCE_CATEGORIES)})")
    if not rule.detection.parsed_condition:
        errors.append("Rule has no evaluable condition")

    if errors:
        return ValidationResult(valid=False, errors=errors, rule=rule)

    return ValidationResult(
        valid=True, errors=[], rule=rule, mitre_techniques=extract_mitre_techniques(rule)
    )
