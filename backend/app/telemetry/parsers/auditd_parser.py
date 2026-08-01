"""
Parses real Linux auditd log lines into NormalizedEvent objects.

Grounded in the real auditd record format, e.g.:

  type=SYSCALL msg=audit(1532489108.216:3721): arch=c000003e syscall=59
    success=yes exit=0 ppid=10627 pid=20240 auid=1000 uid=0 gid=0
    comm="cat" exe="/usr/bin/cat" key="procmon"
  type=EXECVE msg=audit(1532489108.216:3721): argc=2 a0="cat" a1="10-procmon.rules"

A SYSCALL record and its paired EXECVE record share the same audit ID
(the number after the colon in msg=audit(...)). We correlate on that ID,
pull comm/exe/pid/ppid/uid/key from SYSCALL, and rebuild the full argv
(and hence a CommandLine-equivalent string) from EXECVE's a0..aN fields.
"""
from __future__ import annotations

import re
import shlex
from typing import Iterable

from app.telemetry.schema import NormalizedEvent

_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
_AUDIT_ID_RE = re.compile(r"audit\(([\d.]+):(\d+)\)")


def _parse_kv(line: str) -> dict[str, str]:
    out = {}
    for key, val in _KV_RE.findall(line):
        out[key] = val.strip('"')
    return out


def parse_auditd_batch(lines: Iterable[str]) -> list[NormalizedEvent]:
    """Correlate SYSCALL + EXECVE record pairs sharing an audit id into events."""
    syscall_by_id: dict[str, dict] = {}
    execve_by_id: dict[str, dict] = {}

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        m = _AUDIT_ID_RE.search(line)
        if not m:
            continue
        audit_id = m.group(2)
        kv = _parse_kv(line)
        if line.startswith("type=SYSCALL"):
            syscall_by_id[audit_id] = kv
        elif line.startswith("type=EXECVE"):
            execve_by_id[audit_id] = kv

    events = []
    for audit_id, sys_kv in syscall_by_id.items():
        exec_kv = execve_by_id.get(audit_id, {})
        argv = []
        if "argc" in exec_kv:
            try:
                argc = int(exec_kv["argc"])
            except ValueError:
                argc = 0
            for i in range(argc):
                arg = exec_kv.get(f"a{i}")
                if arg is not None:
                    argv.append(arg)
        command_line = " ".join(shlex.quote(a) if " " in a else a for a in argv) if argv else None

        events.append(
            NormalizedEvent(
                source_type="auditd",
                Image=sys_kv.get("exe"),
                CommandLine=command_line,
                User=sys_kv.get("uid"),
                ProcessId=int(sys_kv["pid"]) if sys_kv.get("pid", "").isdigit() else None,
                ParentProcessId=int(sys_kv["ppid"]) if sys_kv.get("ppid", "").isdigit() else None,
                comm=sys_kv.get("comm"),
                exe=sys_kv.get("exe"),
                key=sys_kv.get("key") if sys_kv.get("key") != "(null)" else None,
                raw={**sys_kv, **{f"execve_{k}": v for k, v in exec_kv.items()}},
            )
        )
    return events
