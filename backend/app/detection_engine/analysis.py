from __future__ import annotations

from app.mitre.data import all_techniques


def build_coverage_report(
    rule_techniques: dict[str, list[str]],  # rule_version_id -> [technique_ids]
    verified_techniques_by_rule_version: dict[str, set[str]],  # rule_version_id -> verified technique_ids
) -> list[dict]:
    """
    For every technique in the curated MITRE library, determine:
      - has_rule: is any rule tagged with this technique?
      - rule_passes: did any rule for this technique receive a verified
        brute-force confirmation for that specific (rule_version_id, technique_id) pair?
      - verification_state: whether the rule is passing, declared but not yet verified,
        or not applicable for this technique.
    This directly implements FR-09 (coverage report / blind-spot list).
    """
    technique_to_rule_versions: dict[str, list[str]] = {t: [] for t in all_techniques()}
    for rule_version_id, techniques in rule_techniques.items():
        for t in techniques:
            technique_to_rule_versions.setdefault(t, []).append(rule_version_id)

    report = []
    for technique_id, meta in all_techniques().items():
        rule_version_ids = technique_to_rule_versions.get(technique_id, [])
        has_rule = len(rule_version_ids) > 0
        rule_passes = any(
            technique_id in verified_techniques_by_rule_version.get(rv, set())
            for rv in rule_version_ids
        )
        verification_state = "no_rule"
        if has_rule:
            verification_state = "passing" if rule_passes else "declared_not_verified"
        report.append(
            {
                "technique_id": technique_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "has_rule": has_rule,
                "rule_passes": rule_passes,
                "verification_state": verification_state,
                "blind_spot": not has_rule or not rule_passes,
            }
        )
    return report

def build_drift_report(
    history: list[dict],
) -> list[dict]:
    """
    Detect drift between consecutive evaluations of the same rule
    against the same technique.

    Detects both directions:
      True  -> False = Was firing -> Now not firing
      False -> True  = Was not firing -> Now firing
    """

    by_rule_and_technique: dict[tuple[str, str], list[dict]] = {}

    # Group evaluations by rule + technique
    for row in history:
        rule_id = row.get("rule_id")
        technique_id = row.get("technique_id")

        if not rule_id or not technique_id:
            continue

        key = (rule_id, technique_id)
        by_rule_and_technique.setdefault(key, []).append(row)

    drifted = []

    for (rule_id, technique_id), rows in by_rule_and_technique.items():

        # Oldest -> newest
        rows_sorted = sorted(
            rows,
            key=lambda r: r.get("evaluated_at", ""),
        )

        for previous, current in zip(rows_sorted, rows_sorted[1:]):

            previous_matched = bool(previous.get("matched"))
            current_matched = bool(current.get("matched"))

            # No change in firing state = no drift
            if previous_matched == current_matched:
                continue

            # Drift must represent a different rule version
            if previous.get("rule_version_id") == current.get("rule_version_id"):
                continue

            # Explicitly identify the direction
            if previous_matched and not current_matched:
                direction = "Was firing → Now not firing"
            elif not previous_matched and current_matched:
                direction = "Was not firing → Now firing"
            else:
                continue

            drifted.append(
                {
                    "rule_id": rule_id,

                    # Current version is the version that caused the drift
                    "rule_version_id": current.get("rule_version_id"),

                    "previous_rule_version_id": previous.get(
                        "rule_version_id"
                    ),

                    "detection_result_id": current.get(
                        "detection_result_id"
                    ),

                    "technique_id": technique_id,

                    # Previous/current firing state
                    "previous_result": previous_matched,
                    "current_result": current_matched,

                    # Human-readable direction
                    "direction": direction,

                    # Timestamp of the new evaluation
                    "detected_at": current.get("evaluated_at"),

                    # Keep both versions of the rule for comparison
                    "previous_rule_content": previous.get(
                        "rule_content"
                    ),

                    "current_rule_content": current.get(
                        "rule_content"
                    ),
                }
            )

    return drifted


