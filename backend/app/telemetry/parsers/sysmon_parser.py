"""
Parses real Sysmon "Process Create" (Event ID 1) text/XML exports into
NormalizedEvent objects.

Handles two real-world shapes:
  1. The plain-text EventData block Sysmon/Event Viewer prints, e.g.:
       Process Create:
       RuleName: -
       UtcTime: 2024-04-28 22:08:22.025
       ProcessGuid: {a23eae89-bd56-5903-0000-0010e9d95e00}
       ProcessId: 6228
       Image: C:\\Windows\\System32\\wbem\\WmiPrvSE.exe
       CommandLine: C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding
       ...
  2. A dict already shaped like Sysmon's EventData (e.g. from a JSON export
     via Winlogbeat), with the same field names.
"""
from __future__ import annotations

import re
from typing import Iterable

from app.telemetry.schema import NormalizedEvent

_LINE_RE = re.compile(r"^([A-Za-z]+):\s?(.*)$")


def parse_sysmon_text_block(text: str) -> NormalizedEvent:
    """Parse one 'Process Create: ... ' EventData text block into a NormalizedEvent."""
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Process Create"):
            continue
        m = _LINE_RE.match(line)
        if m:
            fields[m.group(1)] = m.group(2).strip()
    return _fields_to_event(fields)


def parse_sysmon_dict(fields: dict) -> NormalizedEvent:
    """Parse an already-structured Sysmon EventData dict (e.g. from JSON/Winlogbeat)."""
    return _fields_to_event(fields)


def _fields_to_event(fields: dict) -> NormalizedEvent:
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    return NormalizedEvent(
        source_type="sysmon",
        sysmon_event_id=1,
        timestamp=fields.get("UtcTime", ""),
        Image=fields.get("Image"),
        OriginalFileName=fields.get("OriginalFileName"),
        CommandLine=fields.get("CommandLine"),
        CurrentDirectory=fields.get("CurrentDirectory"),
        User=fields.get("User"),
        ParentImage=fields.get("ParentImage"),
        ParentCommandLine=fields.get("ParentCommandLine"),
        ParentUser=fields.get("ParentUser"),
        ProcessId=_int(fields.get("ProcessId")),
        ParentProcessId=_int(fields.get("ParentProcessId")),
        IntegrityLevel=fields.get("IntegrityLevel"),
        raw=fields,
    )


def parse_sysmon_batch(blocks: Iterable[str]) -> list[NormalizedEvent]:
    return [parse_sysmon_text_block(b) for b in blocks if b.strip()]
