"""
Local MITRE ATT&CK technique metadata for the curated technique library this
project ships with. Technique IDs, names, and tactic assignments verified
against the public MITRE ATT&CK knowledge base (attack.mitre.org).

For the full stretch-goal integration, `mitreattack.stix20.MitreAttackData`
(the official mitre-attack/mitreattack-python library) can load the complete
enterprise-attack STIX bundle and replace this table without changing the
rest of the app — see mitre/attack_data_loader.py.
"""
from __future__ import annotations

TECHNIQUES: dict[str, dict] = {
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence"},
    "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
}


def get_technique(technique_id: str) -> dict | None:
    return TECHNIQUES.get(technique_id)


def all_techniques() -> dict[str, dict]:
    return TECHNIQUES
