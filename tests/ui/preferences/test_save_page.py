"""GTK adapter tests for the Save & Apply page."""

from pathlib import Path
from unittest import mock

import pytest


@pytest.fixture
def save_state():
    from src.core.preferences_save import PreferenceSaveState

    return PreferenceSaveState(
        freshclam_config=None,
        clamd_config=None,
        freshclam_conf_path="/tmp/freshclam.conf",
        clamd_conf_path="/tmp/clamd.conf",
        clamd_available=False,
    )


@pytest.fixture
def save_page(mock_gi_modules, save_state):
    from src.ui.preferences.save_page import SavePage

    return SavePage(
        mock.MagicMock(),
        mock.MagicMock(return_value=save_state),
        mock.MagicMock(),
        mock.MagicMock(),
        {},
        {},
        {},
        {},
    )


class TestSavePagePresentation:
    def test_flatpak_helper_probe_returns_to_main_loop(self, mock_gi_modules, save_page):
        from src.core.privileged_helper import PrivilegedHelperState, PrivilegedHelperStatus

        status = PrivilegedHelperStatus(
            state=PrivilegedHelperState.INSTALLABLE,
            package_name="clamui-privileged-helper",
            version="1.2.3",
        )
        with (
            mock.patch(
                "src.ui.preferences.save_page.get_privileged_helper_status",
                return_value=status,
            ),
            mock.patch("src.ui.preferences.save_page.GLib.idle_add") as idle_add,
            mock.patch.object(save_page, "_render_privileged_helper_status") as render,
        ):
            save_page._probe_privileged_helper_status()

        idle_add.assert_called_once_with(render, status)


class TestSavePageWorkflowAdapter:
    def test_invalid_update_renders_error_without_starting_worker_or_mutating_live_config(
        self, save_page
    ):
        from src.core.clamav_config import ClamAVConfig, ClamAVConfigValue
        from src.core.preferences_save import PreferenceSaveState
        from src.ui.preferences.save_page import (
            DatabasePage,
            OnAccessPage,
            ScannerPage,
            ScheduledPage,
        )

        live_config = ClamAVConfig(
            file_path=Path("/tmp/freshclam.conf"),
            values={"Checks": [ClamAVConfigValue(value="12", line_number=1)]},
            raw_lines=["Checks 12\n"],
        )
        save_page._state_provider.return_value = PreferenceSaveState(
            freshclam_config=live_config,
            clamd_config=None,
            freshclam_conf_path="/tmp/freshclam.conf",
            clamd_conf_path="/tmp/clamd.conf",
            clamd_available=False,
        )
        button = mock.MagicMock()

        with (
            mock.patch.object(DatabasePage, "collect_data", return_value={"Checks": "51"}),
            mock.patch.object(ScannerPage, "collect_data", return_value={}),
            mock.patch.object(OnAccessPage, "collect_data", return_value={}),
            mock.patch.object(ScheduledPage, "collect_data", return_value={}),
            mock.patch("src.ui.preferences.save_page.threading.Thread") as thread,
            mock.patch.object(save_page, "_show_error_dialog") as error_dialog,
        ):
            save_page._on_save_clicked(button)

        thread.assert_not_called()
        assert error_dialog.call_count == 1
        assert "Checks" in error_dialog.call_args.args[1]
        assert live_config.get_value("Checks") == "12"
        assert live_config.to_string() == "Checks 12\n"
        assert save_page._is_saving is False
        button.set_sensitive.assert_has_calls([mock.call(False), mock.call(True)])

    def test_completion_commits_durable_config_before_rendering_partial_failure(
        self, save_page, save_state
    ):
        from src.core.clamav_config import ClamAVConfig
        from src.core.preferences_save import DurableGroup, PreferenceSaveResult, SaveStatus

        committed = {"freshclam_config": None}
        durable_config = ClamAVConfig(file_path=Path("/tmp/freshclam.conf"))
        result = PreferenceSaveResult(
            status=SaveStatus.PARTIALLY_APPLIED,
            freshclam_config=durable_config,
            durable_groups=(DurableGroup.CLAMAV_CONFIGS,),
            error="scheduler failed",
        )

        def commit_durable_result(completed_result, captured_state):
            assert captured_state is save_state
            committed["freshclam_config"] = completed_result.freshclam_config

        def render_partial_failure(_title, message):
            assert committed["freshclam_config"] is durable_config
            assert "scheduler failed" in message

        save_page._result_handler = commit_durable_result
        save_page._show_error_dialog = mock.MagicMock(side_effect=render_partial_failure)
        button = mock.MagicMock()

        save_page._complete_save(result, save_state, button)

        save_page._show_error_dialog.assert_called_once()
        assert save_page._is_saving is False
        button.set_sensitive.assert_called_once_with(True)

    def test_completion_renders_writer_warning_after_committing_config(self, save_page, save_state):
        from src.core.clamav_config import ClamAVConfig
        from src.core.preferences_save import DurableGroup, PreferenceSaveResult, SaveStatus

        committed = {"freshclam_config": None}
        durable_config = ClamAVConfig(file_path=Path("/tmp/freshclam.conf"))
        warning = "Staging cleanup was delayed"
        result = PreferenceSaveResult(
            status=SaveStatus.SAVED,
            freshclam_config=durable_config,
            durable_groups=(DurableGroup.CLAMAV_CONFIGS,),
            config_write_warning=warning,
        )

        def commit_durable_result(completed_result, captured_state):
            assert captured_state is save_state
            committed["freshclam_config"] = completed_result.freshclam_config

        def render_warning(title, message):
            assert committed["freshclam_config"] is durable_config
            assert warning in f"{title}\n{message}"

        save_page._result_handler = commit_durable_result
        save_page._show_success_dialog = mock.MagicMock(side_effect=render_warning)
        button = mock.MagicMock()

        save_page._complete_save(result, save_state, button)

        save_page._show_success_dialog.assert_called_once()
        assert save_page._is_saving is False
        button.set_sensitive.assert_called_once_with(True)
