"""Build normalized process-creation telemetry from resolved Atomic commands."""
from __future__ import annotations

import random
from pathlib import PurePath

from app.telemetry.schema import NormalizedEvent
from app.telemetry.generators.atomic_red_team_loader import AtomicTest


HOST_WIN = "LAB-WIN10"
HOST_LINUX = "lab-ubuntu-01"


def _win_event(**kwargs) -> NormalizedEvent:
    defaults = dict(
        source_type="synthetic",
        sysmon_event_id=1,
        host=HOST_WIN,
        User="LAB-WIN10\\analyst",
        ParentImage="C:\\Windows\\explorer.exe",
        ParentCommandLine="C:\\Windows\\explorer.exe",
        ParentProcessId=4200,
        IntegrityLevel="Medium",
    )
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


def _linux_event(**kwargs) -> NormalizedEvent:
    defaults = dict(source_type="synthetic", host=HOST_LINUX, User="1000")
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


EXECUTOR_IMAGES = {
    "command_prompt": "C:\\Windows\\System32\\cmd.exe",
    "powershell": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "sh": "/bin/sh",
    "bash": "/bin/bash",
}


def build_atomic_telemetry(test: AtomicTest, run_id: str) -> NormalizedEvent:
    """Create one Sysmon/auditd-shaped event for a resolved Atomic command."""
    image = EXECUTOR_IMAGES[test.executor_name]
    common = dict(
        Image=image,
        CommandLine=test.resolved_command_line,
        ProcessId=random.randint(2000, 9000),
        technique_id=test.technique_id,
        simulation_run_id=run_id,
        raw={
            "atomic_test_name": test.test_name,
            "atomic_test_guid": test.test_guid,
            "atomic_executor": test.executor_name,
            "atomic_supported_platforms": list(test.supported_platforms),
        },
    )
    if test.executor_name in {"command_prompt", "powershell"}:
        return _win_event(
            **common,
            OriginalFileName="PowerShell.EXE" if test.executor_name == "powershell" else "cmd.exe",
        )
    return _linux_event(**common, comm=PurePath(image).name, exe=image)
