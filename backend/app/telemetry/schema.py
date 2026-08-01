"""
Normalized event schema.

Every telemetry source (real Sysmon logs, real auditd logs, or the synthetic
generator) produces a flat dict in this shape before it reaches the
detection engine. Field names intentionally mirror the vendor field names
used inside real Sigma rules (Image, CommandLine, ParentImage, User, ...)
so that community Sigma rules written for Sysmon/auditd "just work" against
normalized events without a translation layer.

Sysmon Event ID 1 (Process Create) field names are taken from the real
Sysmon schema: UtcTime, ProcessGuid, ProcessId, Image, FileVersion,
Description, Product, Company, OriginalFileName, CommandLine,
CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId,
IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage,
ParentCommandLine, ParentUser.

Linux auditd EXECVE/SYSCALL field names are taken from the real auditd
schema: comm, exe, pid, ppid, uid, auid, key, plus the argv list rebuilt
from EXECVE's a0..aN fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import uuid


@dataclass
class NormalizedEvent:
    # Common envelope
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host: str = "lab-host-01"
    source_type: str = "synthetic"  # sysmon | auditd | synthetic
    sysmon_event_id: Optional[int] = None  # 1, 3, 11, 13, ...

    # Process fields (Sysmon EventID 1 / auditd EXECVE, normalized)
    Image: Optional[str] = None
    OriginalFileName: Optional[str] = None
    CommandLine: Optional[str] = None
    CurrentDirectory: Optional[str] = None
    User: Optional[str] = None
    ParentImage: Optional[str] = None
    ParentCommandLine: Optional[str] = None
    ParentUser: Optional[str] = None
    ProcessId: Optional[int] = None
    ParentProcessId: Optional[int] = None
    IntegrityLevel: Optional[str] = None

    # Registry (Sysmon EventID 13)
    TargetObject: Optional[str] = None
    Details: Optional[str] = None

    # Network (Sysmon EventID 3)
    DestinationIp: Optional[str] = None
    DestinationPort: Optional[int] = None

    # Linux-specific raw fields kept for auditd-native rules
    comm: Optional[str] = None
    exe: Optional[str] = None
    key: Optional[str] = None

    # provenance
    technique_id: Optional[str] = None
    simulation_run_id: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Flat dict as handed to the detection engine. None fields dropped
        so Sigma field-existence semantics behave the way they do against
        real sparse log data."""
        d = {k: v for k, v in self.__dict__.items() if v is not None and k != "raw"}
        return d
