"""Tests for raw-filename rendering and finding deltas in the scan progress widget."""

from types import SimpleNamespace
from unittest.mock import MagicMock


def _clear_src_modules():
    import sys

    for module_name in [name for name in sys.modules if name.startswith("src.")]:
        del sys.modules[module_name]


def test_live_threat_row_sanitizes_surrogate_filename(mock_gi_modules):
    """GTK receives only a display-safe version of a raw filesystem path."""
    from src.ui.scan.scan_progress_widget import ScanProgressWidget

    row = MagicMock()
    mock_gi_modules["adw"].ActionRow.side_effect = lambda: row
    widget = object.__new__(ScanProgressWidget)
    widget._live_threat_list = MagicMock()
    widget._threat_group = MagicMock()
    widget._live_threat_count = 1

    widget._append_threat_row("/tmp/infected_\udcff", "TestThreat")

    row.set_title.assert_called_once_with("infected_\ufffd")
    row.set_tooltip_text.assert_called_once_with("/tmp/infected_\ufffd")
    _clear_src_modules()


def test_widget_renders_each_new_threat_delta_once(mock_gi_modules):
    """Progress count resets cannot hide a finding carried by its delta."""
    from src.ui.scan.scan_progress_widget import ScanProgressWidget

    widget = object.__new__(ScanProgressWidget)
    widget._paused = False
    widget._bar = MagicMock()
    widget._status_label = MagicMock()
    widget._current_file_row = MagicMock()
    widget._stats_row = MagicMock()
    widget._live_threat_count = 0
    rendered = []
    widget._append_threat_row = lambda path, name: rendered.append((path, name))
    progress = SimpleNamespace(
        percentage=None,
        current_file="",
        files_scanned=1,
        files_total=None,
        new_threats=(("/tmp/one", "Threat.One"), ("/tmp/two", "Threat.Two")),
    )

    widget.update(progress)

    assert rendered == list(progress.new_threats)
    assert widget._live_threat_count == 2
    _clear_src_modules()
