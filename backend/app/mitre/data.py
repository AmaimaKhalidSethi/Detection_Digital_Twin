"""Compatibility wrapper for MITRE ATT&CK technique metadata.

The app uses this module through the existing public functions, but the actual
implementation now comes from the STIX-backed loader in attack_data_loader.py.
"""
from __future__ import annotations

from app.mitre.attack_data_loader import all_techniques as _all_techniques
from app.mitre.attack_data_loader import get_technique as _get_technique


def get_technique(technique_id: str) -> dict | None:
    return _get_technique(technique_id)


def all_techniques() -> dict[str, dict]:
    return _all_techniques()
