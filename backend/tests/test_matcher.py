from sigma.rule import SigmaRule

from app.detection_engine.matcher import RuleMatcher


def _rule(condition: str, extra_detection: str = "") -> SigmaRule:
    yaml_text = f"""
title: test rule
status: test
description: test
logsource:
    category: process_creation
    product: windows
detection:
    sel_a:
        FieldA: valueA
    sel_b:
        FieldB|contains: 'needle'
    sel_num:
        EventID: 1
{extra_detection}
    condition: {condition}
"""
    return SigmaRule.from_yaml(yaml_text)


def test_and_condition_true():
    matcher = RuleMatcher(_rule("sel_a and sel_b"))
    assert matcher.match({"FieldA": "valueA", "FieldB": "a needle in haystack"}).matched


def test_and_condition_false_missing_field():
    matcher = RuleMatcher(_rule("sel_a and sel_b"))
    assert not matcher.match({"FieldA": "valueA"}).matched


def test_or_condition():
    matcher = RuleMatcher(_rule("sel_a or sel_b"))
    assert matcher.match({"FieldA": "valueA"}).matched
    assert matcher.match({"FieldB": "has needle here"}).matched
    assert not matcher.match({"FieldA": "nope", "FieldB": "nope"}).matched


def test_not_condition():
    matcher = RuleMatcher(_rule("sel_a and not sel_b"))
    assert matcher.match({"FieldA": "valueA"}).matched
    assert not matcher.match({"FieldA": "valueA", "FieldB": "needle"}).matched


def test_contains_is_case_insensitive():
    matcher = RuleMatcher(_rule("sel_b"))
    assert matcher.match({"FieldB": "A NEEDLE In Haystack"}).matched


def test_numeric_field_match():
    matcher = RuleMatcher(_rule("sel_num"))
    assert matcher.match({"EventID": 1}).matched
    assert not matcher.match({"EventID": 2}).matched


def test_endswith_modifier():
    rule = SigmaRule.from_yaml(
        """
title: t
status: test
description: d
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\\\\powershell.exe'
    condition: sel
"""
    )
    matcher = RuleMatcher(rule)
    assert matcher.match({"Image": "C:\\Windows\\System32\\powershell.exe"}).matched
    assert not matcher.match({"Image": "C:\\Windows\\System32\\cmd.exe"}).matched
