"""
Synthetic telemetry generator.

Produces NormalizedEvent objects that reproduce the *observable* telemetry
a real (benign) execution of a MITRE ATT&CK technique would generate, without
running anything harmful. Field shapes mirror real Sysmon Event ID 1 /
auditd EXECVE output (see parsers/ for the real-format references this is
grounded in).

This is the offline equivalent of running Atomic Red Team on a lab VM and
capturing Sysmon/auditd logs — used when no live VM run is available, and
also used to build the deterministic regression telemetry set that drift
detection (FR-10) compares against over time.
"""
from __future__ import annotations

import random
from typing import Callable

from app.telemetry.schema import NormalizedEvent
from app.telemetry.generators.atomic_red_team_loader import (
    atomic_coverage_gaps,
    get_atomic_test,
    load_atomic_tests,
)
from app.telemetry.generators.atomic_telemetry_builder import (
    _linux_event,
    _win_event,
    build_atomic_telemetry,
)


# ---- per-technique simulation functions -----------------------------------

def sim_t1059_001_powershell(run_id: str) -> list[NormalizedEvent]:
    """T1059.001 PowerShell — encoded command execution (Emotet-style, benign payload)."""
    encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    ev = _win_event(
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        OriginalFileName="PowerShell.EXE",
        CommandLine=f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded}",
        ProcessId=random.randint(2000, 9000),
        technique_id="T1059.001",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_t1057_process_discovery(run_id: str) -> list[NormalizedEvent]:
    """T1057 Process Discovery — tasklist.exe enumeration."""
    ev = _win_event(
        Image="C:\\Windows\\System32\\tasklist.exe",
        OriginalFileName="tasklist.exe",
        CommandLine="tasklist.exe /v /fo csv",
        ProcessId=random.randint(2000, 9000),
        technique_id="T1057",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_t1082_system_info_discovery(run_id: str) -> list[NormalizedEvent]:
    """T1082 System Information Discovery — systeminfo.exe."""
    ev = _win_event(
        Image="C:\\Windows\\System32\\systeminfo.exe",
        OriginalFileName="systeminfo.exe",
        CommandLine="systeminfo.exe",
        ProcessId=random.randint(2000, 9000),
        technique_id="T1082",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_t1547_001_registry_run_key(run_id: str) -> list[NormalizedEvent]:
    """T1547.001 Registry Run Key persistence — reg.exe adding an autostart entry."""
    ev = _win_event(
        Image="C:\\Windows\\System32\\reg.exe",
        OriginalFileName="reg.exe",
        CommandLine=(
            'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v Updater /t REG_SZ /d "C:\\Users\\analyst\\updater.exe" /f'
        ),
        ProcessId=random.randint(2000, 9000),
        technique_id="T1547.001",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_t1053_005_scheduled_task(run_id: str) -> list[NormalizedEvent]:
    """T1053.005 Scheduled Task persistence — schtasks.exe."""
    ev = _win_event(
        Image="C:\\Windows\\System32\\schtasks.exe",
        OriginalFileName="schtasks.exe",
        CommandLine='schtasks.exe /create /sc minute /mo 5 /tn "Updater" /tr C:\\Users\\analyst\\updater.exe',
        ProcessId=random.randint(2000, 9000),
        technique_id="T1053.005",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_t1003_001_lsass_dump(run_id: str) -> list[NormalizedEvent]:
    """T1003.001 LSASS Memory — benign proc-dump-style access to lsass.exe process."""
    ev = _win_event(
        Image="C:\\Windows\\Temp\\procdump.exe",
        OriginalFileName="procdump.exe",
        CommandLine="procdump.exe -accepteula -ma lsass.exe lsass.dmp",
        ProcessId=random.randint(2000, 9000),
        technique_id="T1003.001",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_linux_t1082_uname(run_id: str) -> list[NormalizedEvent]:
    """T1082 System Information Discovery (Linux) — uname -a."""
    ev = _linux_event(
        Image="/usr/bin/uname",
        CommandLine="uname -a",
        comm="uname",
        exe="/usr/bin/uname",
        technique_id="T1082",
        simulation_run_id=run_id,
    )
    return [ev]


def sim_linux_t1053_003_cron(run_id: str) -> list[NormalizedEvent]:
    """T1053.003 Cron persistence (Linux) — crontab edit."""
    ev = _linux_event(
        Image="/usr/bin/crontab",
        CommandLine="crontab -l",
        comm="crontab",
        exe="/usr/bin/crontab",
        technique_id="T1053.003",
        simulation_run_id=run_id,
    )
    return [ev]


TECHNIQUE_SIMULATIONS: dict[str, Callable[[str], list[NormalizedEvent]]] = {
    "T1059.001": sim_t1059_001_powershell,
    "T1057": sim_t1057_process_discovery,
    "T1082": sim_t1082_system_info_discovery,
    "T1547.001": sim_t1547_001_registry_run_key,
    "T1053.005": sim_t1053_005_scheduled_task,
    "T1003.001": sim_t1003_001_lsass_dump,
    "T1082-linux": sim_linux_t1082_uname,
    "T1053.003": sim_linux_t1053_003_cron,
}


def run_simulation(technique_id: str, run_id: str) -> list[NormalizedEvent]:
    fn = TECHNIQUE_SIMULATIONS.get(technique_id)
    if fn is not None:
        return fn(run_id)
    from app.telemetry.generators.atomic_red_team_loader import load_all_atomic_tests
    all_tests = load_all_atomic_tests()
    tests = all_tests.get(technique_id)
    if not tests:
        raise ValueError(f"No simulation defined for technique {technique_id}")
    return [build_atomic_telemetry(test, run_id) for test in tests]


def available_simulation_techniques() -> list[str]:
    """All hand-written and usable Atomic-backed technique IDs."""
    return sorted(set(TECHNIQUE_SIMULATIONS) | set(load_atomic_tests()))


def simulation_coverage_gaps() -> list[str]:
    """Vendored Atomic technique IDs not runnable by either simulator path."""
    return sorted(set(atomic_coverage_gaps()) - set(TECHNIQUE_SIMULATIONS))


# ---- benign baseline (for false-positive / specificity testing) -----------

def generate_benign_baseline(run_id: str, count: int = 25) -> list[NormalizedEvent]:
    """A batch of ordinary admin/user activity, used to measure a rule's
    false-positive rate (NFR performance target, Section 6/15 of the SDD)."""
    benign_commands = [
        ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\analyst\\notes.txt"),
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --profile-directory=Default"),
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"),
        ("C:\\Windows\\explorer.exe", "explorer.exe"),
        ("C:\\Windows\\System32\\backgroundTaskHost.exe", "backgroundTaskHost.exe -ServerName:App"),
    ]
    events = []
    for i in range(count):
        image, cmd = random.choice(benign_commands)
        events.append(
            _win_event(
                Image=image,
                CommandLine=cmd,
                ProcessId=random.randint(2000, 9000),
                simulation_run_id=run_id,
            )
        )
    return events
