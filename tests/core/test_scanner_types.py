# ClamUI Scanner Types Tests
"""Unit tests for the scanner_types module."""

import pytest

from src.core.scanner_types import ScanProgress, ScanResult, ScanStatus, ThreatDetail


class TestScanStatus:
    """Tests for ScanStatus enum."""

    def test_scan_status_values(self):
        """Test that ScanStatus has expected values."""
        assert ScanStatus.CLEAN.value == "clean"
        assert ScanStatus.INFECTED.value == "infected"
        assert ScanStatus.ERROR.value == "error"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_scan_status_members(self):
        """Test that ScanStatus has all expected members."""
        members = list(ScanStatus)
        assert len(members) == 4
        assert ScanStatus.CLEAN in members
        assert ScanStatus.INFECTED in members
        assert ScanStatus.ERROR in members
        assert ScanStatus.CANCELLED in members


class TestThreatDetail:
    """Tests for ThreatDetail dataclass."""

    def test_threat_detail_creation(self):
        """Test creating a ThreatDetail instance."""
        threat = ThreatDetail(
            file_path="/path/to/file.exe",
            threat_name="Trojan.Generic",
            category="Trojan",
            severity="HIGH",
        )
        assert threat.file_path == "/path/to/file.exe"
        assert threat.threat_name == "Trojan.Generic"
        assert threat.category == "Trojan"
        assert threat.severity == "HIGH"

    def test_threat_detail_equality(self):
        """Test ThreatDetail equality comparison."""
        threat1 = ThreatDetail(
            file_path="/path/to/file.exe",
            threat_name="Trojan.Generic",
            category="Trojan",
            severity="HIGH",
        )
        threat2 = ThreatDetail(
            file_path="/path/to/file.exe",
            threat_name="Trojan.Generic",
            category="Trojan",
            severity="HIGH",
        )
        assert threat1 == threat2


class TestScanProgress:
    """Tests for ScanProgress dataclass."""

    def test_scan_progress_with_none_total(self):
        """Test ScanProgress with unknown total (None)."""
        progress = ScanProgress(
            current_file="/path/to/file.txt",
            files_scanned=10,
            files_total=None,
            infected_count=0,
        )
        assert progress.files_total is None

    def test_percentage_with_valid_total(self):
        """Test percentage calculation with known total."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=25,
            files_total=100,
            infected_count=0,
        )
        assert progress.percentage == 25.0

    def test_percentage_at_zero_scanned(self):
        """Test percentage at start of scan (0 files scanned)."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=0,
            files_total=100,
            infected_count=0,
        )
        assert progress.percentage == 0.0

    def test_percentage_at_completion(self):
        """Test percentage at 100% completion."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=100,
            files_total=100,
            infected_count=0,
        )
        assert progress.percentage == 100.0

    def test_percentage_with_none_total_returns_none(self):
        """Test that percentage returns None when total is unknown."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=50,
            files_total=None,
            infected_count=0,
        )
        assert progress.percentage is None

    def test_percentage_with_zero_total_returns_none(self):
        """Test that percentage returns None when total is 0 (empty directory)."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=0,
            files_total=0,
            infected_count=0,
        )
        assert progress.percentage is None

    def test_percentage_fractional_value(self):
        """Test percentage calculation produces fractional values."""
        progress = ScanProgress(
            current_file="/file.txt",
            files_scanned=1,
            files_total=3,
            infected_count=0,
        )
        assert progress.percentage == pytest.approx(33.333, rel=0.01)


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_is_clean_true(self):
        """Test is_clean property returns True for CLEAN status."""
        result = ScanResult(
            status=ScanStatus.CLEAN,
            path="/path/to/scan",
            stdout="Scanning...",
            stderr="",
            exit_code=0,
            infected_files=[],
            scanned_files=100,
            scanned_dirs=10,
            infected_count=0,
            error_message=None,
            threat_details=[],
        )
        assert result.is_clean is True
        assert result.has_threats is False

    def test_scan_result_is_clean_false_when_infected(self):
        """Test is_clean property returns False for INFECTED status."""
        result = ScanResult(
            status=ScanStatus.INFECTED,
            path="/path/to/scan",
            stdout="Scanning...",
            stderr="",
            exit_code=1,
            infected_files=["/infected.exe"],
            scanned_files=100,
            scanned_dirs=10,
            infected_count=1,
            error_message=None,
            threat_details=[
                ThreatDetail(
                    file_path="/infected.exe",
                    threat_name="Trojan.Generic",
                    category="Trojan",
                    severity="HIGH",
                )
            ],
        )
        assert result.is_clean is False
        assert result.has_threats is True

    def test_scan_result_has_warnings_with_skipped(self):
        """Test has_warnings property with skipped files."""
        result = ScanResult(
            status=ScanStatus.CLEAN,
            path="/path/to/scan",
            stdout="Scanning...",
            stderr="",
            exit_code=0,
            infected_files=[],
            scanned_files=95,
            scanned_dirs=10,
            infected_count=0,
            error_message=None,
            threat_details=[],
            skipped_files=["/no/permission1.txt", "/no/permission2.txt"],
            skipped_count=2,
            warning_message="2 files could not be scanned due to permissions",
        )
        assert result.has_warnings is True

    def test_scan_result_has_warnings_no_skipped(self):
        """Test has_warnings property without skipped files."""
        result = ScanResult(
            status=ScanStatus.CLEAN,
            path="/path/to/scan",
            stdout="Scanning...",
            stderr="",
            exit_code=0,
            infected_files=[],
            scanned_files=100,
            scanned_dirs=10,
            infected_count=0,
            error_message=None,
            threat_details=[],
        )
        assert result.has_warnings is False

    def test_scan_result_error_status(self):
        """Test ScanResult with ERROR status."""
        result = ScanResult(
            status=ScanStatus.ERROR,
            path="/path/to/scan",
            stdout="",
            stderr="Error: ClamAV not found",
            exit_code=2,
            infected_files=[],
            scanned_files=0,
            scanned_dirs=0,
            infected_count=0,
            error_message="ClamAV not found",
            threat_details=[],
        )
        assert result.is_clean is False
        assert result.has_threats is False
        assert result.error_message == "ClamAV not found"

    def test_scan_result_cancelled_status(self):
        """Test ScanResult with CANCELLED status."""
        result = ScanResult(
            status=ScanStatus.CANCELLED,
            path="/path/to/scan",
            stdout="Scanning...",
            stderr="",
            exit_code=-1,
            infected_files=[],
            scanned_files=50,
            scanned_dirs=5,
            infected_count=0,
            error_message="Scan cancelled by user",
            threat_details=[],
        )
        assert result.is_clean is False
        assert result.has_threats is False
