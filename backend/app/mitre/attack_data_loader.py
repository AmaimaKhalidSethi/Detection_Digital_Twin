from __future__ import annotations

from pathlib import Path

from mitreattack.stix20 import MitreAttackData


_DATA_PATH = Path(__file__).resolve().parent / "data" / "enterprise-attack.json"
_ATTACK_DATA = MitreAttackData(str(_DATA_PATH))


def _truncate_description(description: str | None) -> str:
    if not description:
        return ""
    return description[:500]


def _normalize_tactic(phase_name: str | None) -> str | None:
    if not phase_name:
        return None

    return " ".join(word.capitalize() for word in phase_name.split("-"))


def _extract_tactic(technique: dict) -> str | None:
    for kill_chain_phase in technique.get("kill_chain_phases", []):
        if kill_chain_phase.get("kill_chain_name") in {"mitre-attack", "mitre-attack-ics"}:
            return _normalize_tactic(kill_chain_phase.get("phase_name"))

    return None


def get_technique(technique_id: str) -> dict | None:
    technique = _ATTACK_DATA.get_object_by_attack_id(technique_id, "attack-pattern")
    if technique is None:
        return None

    if technique.get("revoked") or technique.get("x_mitre_deprecated"):
        return None

    for reference in technique.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")
            if external_id:
                technique_id = external_id
                break
    else:
        technique_id = technique_id

    tactic = _extract_tactic(technique)

    return {
        "name": technique.get("name"),
        "tactic": tactic,
        "description": _truncate_description(technique.get("description")),
    }


def all_techniques() -> dict[str, dict]:
    techniques: dict[str, dict] = {}

    for technique in _ATTACK_DATA.get_techniques():
        if technique.get("revoked") or technique.get("x_mitre_deprecated"):
            continue

        external_id = None
        for reference in technique.get("external_references", []):
            if reference.get("source_name") == "mitre-attack":
                external_id = reference.get("external_id")
                break

        if not external_id:
            continue

        tactic = _extract_tactic(technique)

        techniques[external_id] = {
            "name": technique.get("name"),
            "tactic": tactic,
            "description": _truncate_description(technique.get("description")),
        }

    return techniques
