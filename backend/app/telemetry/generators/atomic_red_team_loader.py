"""Load safe, process-creation-oriented Atomic Red Team test definitions.

This module only reads the pinned YAML snapshot under ``backend/vendor``. It
never executes the commands it resolves; the telemetry builder uses them as
the observable command-line data for deterministic simulations.
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

import yaml


LOG = logging.getLogger(__name__)
SUPPORTED_EXECUTORS = frozenset({"command_prompt", "sh", "bash", "powershell"})
_PLACEHOLDER = re.compile(r"#\{([^}]+)\}")
_EXTERNAL_DOWNLOAD = re.compile(
    r"https?://|invoke-webrequest|wget\b|curl\b|downloadstring|downloadfile|"
    r"bitsadmin\b|certutil\s.*-urlcache|git\s+clone",
    re.IGNORECASE,
)
VENDOR_ATOMICS = Path(__file__).resolve().parents[3] / "vendor" / "atomic-red-team" / "atomics"


class AtomicTest(NamedTuple):
    """Usable Atomic definition, preserving the requested tuple contract."""

    technique_id: str
    test_name: str
    test_guid: str
    executor_name: str
    resolved_command_line: str
    supported_platforms: tuple[str, ...]


def _has_unresolvable_dependency(test: dict) -> bool:
    """Reject uncertain or download-dependent prerequisites conservatively."""
    dependencies = test.get("dependencies") or []
    if not dependencies:
        return False
    dependency_executor = test.get("dependency_executor_name")
    if dependency_executor and dependency_executor not in SUPPORTED_EXECUTORS:
        return True
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            return True
        prereq = dependency.get("prereq_command")
        get_prereq = dependency.get("get_prereq_command")
        if not prereq or not get_prereq:
            return True
        if _EXTERNAL_DOWNLOAD.search(str(get_prereq)):
            return True
    return False


def _resolve_command(test: dict) -> str | None:
    command = str((test.get("executor") or {}).get("command") or "")
    if not command.strip():
        return None
    arguments = test.get("input_arguments") or {}

    def replace(match: re.Match[str]) -> str:
        argument = arguments.get(match.group(1))
        if not isinstance(argument, dict) or argument.get("default") is None:
            return match.group(0)
        return str(argument["default"])

    resolved = _PLACEHOLDER.sub(replace, command).strip()
    return None if _PLACEHOLDER.search(resolved) else resolved


def _first_usable_test(technique_id: str, document: dict) -> AtomicTest | None:
    for test in document.get("atomic_tests") or []:
        if not isinstance(test, dict):
            continue
        executor = test.get("executor") or {}
        executor_name = executor.get("name")
        if executor_name not in SUPPORTED_EXECUTORS:
            continue
        if _has_unresolvable_dependency(test):
            LOG.info("Skipping Atomic %s / %s: unresolved dependency", technique_id, test.get("name"))
            continue
        command = _resolve_command(test)
        if command is None:
            LOG.info("Skipping Atomic %s / %s: unresolved input argument", technique_id, test.get("name"))
            continue
        guid = test.get("auto_generated_guid")
        if not guid:
            LOG.info("Skipping Atomic %s / %s: no test GUID", technique_id, test.get("name"))
            continue
        return AtomicTest(
            technique_id=technique_id,
            test_name=str(test.get("name") or "Unnamed Atomic test"),
            test_guid=str(guid),
            executor_name=str(executor_name),
            resolved_command_line=command,
            supported_platforms=tuple(test.get("supported_platforms") or ()),
        )
    return None


@lru_cache(maxsize=1)
def load_all_atomic_tests() -> dict[str, list[AtomicTest]]:
    """Return all safe process-creation Atomic tests for each technique."""
    tests: dict[str, list[AtomicTest]] = {}
    if not VENDOR_ATOMICS.exists():
        LOG.warning("Atomic Red Team snapshot is not vendored at %s", VENDOR_ATOMICS)
        return tests
    for yaml_path in sorted(VENDOR_ATOMICS.glob("T*/T*.yaml")):
        try:
            document = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as error:
            LOG.warning("Skipping unreadable Atomic definition %s: %s", yaml_path, error)
            continue
        technique_id = document.get("attack_technique") or yaml_path.parent.name
        if not isinstance(technique_id, str) or not technique_id.startswith("T"):
            LOG.warning("Skipping Atomic definition with invalid technique ID: %s", yaml_path)
            continue
        
        technique_tests = []
        for test in document.get("atomic_tests") or []:
            if not isinstance(test, dict):
                continue
            executor = test.get("executor") or {}
            executor_name = executor.get("name")
            if executor_name not in SUPPORTED_EXECUTORS:
                continue
            if _has_unresolvable_dependency(test):
                continue
            command = _resolve_command(test)
            if command is None:
                continue
            guid = test.get("auto_generated_guid")
            if not guid:
                continue
            technique_tests.append(AtomicTest(
                technique_id=technique_id,
                test_name=str(test.get("name") or "Unnamed Atomic test"),
                test_guid=str(guid),
                executor_name=str(executor_name),
                resolved_command_line=command,
                supported_platforms=tuple(test.get("supported_platforms") or ()),
            ))
        if technique_tests:
            tests[technique_id] = technique_tests
    return tests


@lru_cache(maxsize=1)
def load_atomic_tests() -> dict[str, AtomicTest]:
    """Return the first safe process-creation Atomic test for each technique."""
    all_tests = load_all_atomic_tests()
    return {tid: tests[0] for tid, tests in all_tests.items() if tests}


@lru_cache(maxsize=1)
def atomic_coverage_gaps() -> list[str]:
    """Technique IDs present in the vendored corpus but lacking a usable test."""
    all_techniques = {path.parent.name for path in VENDOR_ATOMICS.glob("T*/T*.yaml")}
    return sorted(all_techniques - set(load_atomic_tests()))


def get_atomic_test(technique_id: str) -> AtomicTest | None:
    return load_atomic_tests().get(technique_id)
