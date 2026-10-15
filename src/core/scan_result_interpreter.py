"""Interpret ClamAV backend output into :class:`ScanResult` values.

The public entry points retain the facts only their respective backends know:
``clamscan`` reports summary counts (with live progress as a fallback), while
``clamdscan`` relies on ClamUI's pre-count and reports genuine errors even when
it exits successfully. Shared detection, status-precedence, warning, and result
assembly rules live here.
"""

import re
from collections.abc import Iterable
from enum import Enum

from .scanner_base import (
    collect_clamav_warnings,
    is_genuine_error_line,
    resolve_exit2_status,
)
from .scanner_types import ScanResult, ScanStatus, ThreatDetail
from .threat_classifier import categorize_threat, classify_threat_severity_str


class _Backend(Enum):
    """Backend-specific evidence policy used only by the shared interpreter."""

    CLAMSCAN = "clamscan"
    DAEMON = "daemon"


def interpret_clamscan_result(
    path: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    scanned_files_hint: int = 0,
) -> ScanResult:
    """Interpret standalone ``clamscan`` output.

    ``clamscan`` summary counts are authoritative, including an explicit zero.
    When the bounded output buffer omitted that summary, ``scanned_files_hint``
    preserves the completed-file count observed by live progress parsing.
    """
    scanned_files, scanned_dirs = _extract_clamscan_counts(stdout, scanned_files_hint)
    detections = _extract_detections(
        line for line in stdout.splitlines() if not line.strip().startswith("Scanning ")
    )
    return _interpret_result(
        _Backend.CLAMSCAN,
        path,
        stdout,
        stderr,
        exit_code,
        scanned_files,
        scanned_dirs,
        detections,
    )


def interpret_daemon_result(
    path: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    file_count: int = 0,
    dir_count: int = 0,
) -> ScanResult:
    """Interpret ``clamdscan`` output using ClamUI's pre-counted targets.

    A pre-count of zero means counting was unavailable, rather than proving no
    files were scanned. ``clamdscan`` can also return a successful exit code
    alongside an explicit daemon error reply, which remains an error result.
    """
    return _interpret_result(
        _Backend.DAEMON,
        path,
        stdout,
        stderr,
        exit_code,
        file_count,
        dir_count,
        _extract_detections(stdout.splitlines()),
    )


def _extract_clamscan_counts(stdout: str, scanned_files_hint: int) -> tuple[int, int]:
    """Extract standalone summary counts, falling back only when absent."""
    scanned_files: int | None = None
    scanned_dirs = 0
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Scanned files:"):
            match = re.search(r"Scanned files:\s*(\d+)", line)
            if match:
                scanned_files = int(match.group(1))
        elif line.startswith("Scanned directories:"):
            match = re.search(r"Scanned directories:\s*(\d+)", line)
            if match:
                scanned_dirs = int(match.group(1))

    return (scanned_files_hint if scanned_files is None else scanned_files, scanned_dirs)


def _extract_detections(lines: Iterable[str]) -> list[ThreatDetail]:
    """Extract and classify all ClamAV ``FOUND`` output lines."""
    detections: list[ThreatDetail] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line.endswith("FOUND"):
            continue

        parts = line.rsplit(":", 1)
        if len(parts) != 2:
            continue

        file_path = parts[0].strip()
        threat_part = parts[1].strip()
        threat_name = (
            threat_part.rsplit(" ", 1)[0].strip() if " FOUND" in threat_part else threat_part
        )
        detections.append(
            ThreatDetail(
                file_path=file_path,
                threat_name=threat_name,
                category=categorize_threat(threat_name),
                severity=classify_threat_severity_str(threat_name),
            )
        )
    return detections


def _interpret_result(
    backend: _Backend,
    path: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    scanned_files: int,
    scanned_dirs: int,
    threat_details: list[ThreatDetail],
) -> ScanResult:
    """Apply the shared ClamAV result policy to backend-specific evidence."""
    skipped_files, nonfatal_warnings, hard_error_lines = collect_clamav_warnings(stdout, stderr)
    infected_files = [threat.file_path for threat in threat_details]
    warning_message: str | None = None
    exit2_error_message: str | None = None

    if threat_details:
        # Detections are authoritative even when the command also encountered
        # an error and reported exit code 2.
        status = ScanStatus.INFECTED
        if exit_code == 2 and skipped_files:
            warning_message = f"{len(skipped_files)} file(s) could not be accessed"
    elif exit_code == 0:
        status = ScanStatus.CLEAN
        if backend is _Backend.DAEMON and any(
            is_genuine_error_line(line) for line in hard_error_lines
        ):
            status = ScanStatus.ERROR
    elif exit_code == 1:
        status = ScanStatus.INFECTED
    elif exit_code == 2:
        status, warning_message, exit2_error_message = resolve_exit2_status(
            stdout,
            scanned_files,
            hard_error_lines,
            skipped_files,
            nonfatal_warnings,
            scanned_is_precount=backend is _Backend.DAEMON,
        )
    else:
        status = ScanStatus.ERROR

    error_message = _error_message(
        backend,
        status,
        stdout,
        stderr,
        exit2_error_message,
        hard_error_lines,
    )
    return ScanResult(
        status=status,
        path=path,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        infected_files=infected_files,
        scanned_files=scanned_files,
        scanned_dirs=scanned_dirs,
        infected_count=len(infected_files),
        error_message=error_message,
        threat_details=threat_details,
        skipped_files=skipped_files,
        skipped_count=len(skipped_files),
        warning_message=warning_message,
        nonfatal_warnings=nonfatal_warnings,
    )


def _error_message(
    backend: _Backend,
    status: ScanStatus,
    stdout: str,
    stderr: str,
    exit2_error_message: str | None,
    hard_error_lines: list[str],
) -> str | None:
    """Choose the backend's established error-message fallback sequence."""
    if status is not ScanStatus.ERROR:
        return None

    error_message = exit2_error_message or stderr.strip() or next(iter(hard_error_lines), None)
    if error_message is not None or backend is not _Backend.DAEMON:
        return error_message

    for raw_line in stdout.splitlines():
        candidate = raw_line.strip()
        if candidate and "SCAN SUMMARY" not in candidate:
            return candidate
    return None
