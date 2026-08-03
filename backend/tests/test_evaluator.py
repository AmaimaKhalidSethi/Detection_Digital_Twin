from app.detection_engine.evaluator import evaluate_rule_version_against_events


def _yaml_rule(condition: str) -> str:
    return (
        "title: test rule\n"
        "status: test\n"
        "description: test\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    sel_a:\n"
        "        FieldA: valueA\n"
        f"    condition: {condition}\n"
    )


def test_evaluate_rule_version_against_events_parse_error():
    result = evaluate_rule_version_against_events(
        rule_version_id="rule-1",
        yaml_content="not valid yaml: [",
        events=[{"FieldA": "valueA"}],
    )

    assert result["rule_version_id"] == "rule-1"
    assert result["matched"] is False
    assert result["matched_event_index"] is None
    assert result["parse_error"] is not None
    assert result["failure_reasons"] == []


def test_evaluate_rule_version_against_events_non_match_returns_failure_reasons():
    yaml_content = _yaml_rule("sel_a")
    result = evaluate_rule_version_against_events(
        rule_version_id="rule-2",
        yaml_content=yaml_content,
        events=[{"FieldA": "wrong"}, {"FieldA": "valueA"}],
    )

    assert result["matched"] is True
    assert result["matched_event_index"] == 1
    assert result["parse_error"] is None
    assert result["failure_reasons"] == []


def test_evaluate_rule_version_against_events_first_non_matching_failure_reasons():
    yaml_content = _yaml_rule("sel_a")
    result = evaluate_rule_version_against_events(
        rule_version_id="rule-3",
        yaml_content=yaml_content,
        events=[{"FieldA": "wrong"}, {"FieldA": "still wrong"}],
    )

    assert result["matched"] is False
    assert result["matched_event_index"] is None
    assert result["parse_error"] is None
    assert result["failure_reasons"] == [
        {
            "field": "FieldA",
            "reason": "value_mismatch",
            "expected": "valueA",
            "actual": "wrong",
        }
    ]
