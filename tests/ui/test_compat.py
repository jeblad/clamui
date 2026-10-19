"""Tests for GTK/libadwaita compatibility helpers."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _clear_src_modules():
    modules_to_remove = [mod for mod in sys.modules if mod.startswith("src.")]
    for mod in modules_to_remove:
        del sys.modules[mod]


class TestPresentAboutDialog:
    def test_uses_adw_about_dialog_when_available(self, mock_gi_modules):
        about_dialog = MagicMock()
        mock_gi_modules["adw"].AboutDialog = MagicMock(return_value=about_dialog)
        mock_gi_modules["gtk"].AboutDialog = MagicMock()

        from src.ui.compat import present_about_dialog

        parent = MagicMock()
        present_about_dialog(
            parent,
            app_name="ClamUI",
            version="1.0.0",
            developer_name="Contributors",
            comments="Test",
            website="https://example.com",
            issue_url="https://example.com/issues",
            icon_name="security-high-symbolic",
        )

        mock_gi_modules["adw"].AboutDialog.assert_called_once()
        about_dialog.present.assert_called_once_with(parent)
        mock_gi_modules["gtk"].AboutDialog.assert_not_called()
        _clear_src_modules()

    def test_falls_back_to_gtk_about_dialog_when_adw_dialog_is_unavailable(self, mock_gi_modules):
        gtk_about_dialog = MagicMock()
        mock_gi_modules["gtk"].AboutDialog = MagicMock(return_value=gtk_about_dialog)

        from src.ui import compat

        parent = MagicMock()
        with patch.object(compat, "Adw", SimpleNamespace()):
            compat.present_about_dialog(
                parent,
                app_name="ClamUI",
                version="1.0.0",
                developer_name="Contributors",
                comments="Test",
                website="https://example.com",
                icon_name="security-high-symbolic",
            )

        mock_gi_modules["gtk"].AboutDialog.assert_called_once()
        gtk_about_dialog.set_transient_for.assert_called_once_with(parent)
        gtk_about_dialog.present.assert_called_once_with()
        _clear_src_modules()

    def test_adw_about_dialog_receives_developers_and_translators(self, mock_gi_modules):
        """Contributor and translator credits reach the Adw.AboutDialog."""
        about_dialog = MagicMock()
        mock_gi_modules["adw"].AboutDialog = MagicMock(return_value=about_dialog)

        from src.ui.compat import present_about_dialog

        present_about_dialog(
            None,
            app_name="ClamUI",
            version="1.0.0",
            developers=["Ada https://example.com"],
            translator_credits="Bob <bob@example.com>",
        )

        about_dialog.set_developers.assert_called_once_with(["Ada https://example.com"])
        about_dialog.set_translator_credits.assert_called_once_with("Bob <bob@example.com>")
        _clear_src_modules()

    def test_gtk_about_dialog_lists_developers_as_authors(self, mock_gi_modules):
        """The Gtk fallback shows the contributor list instead of the single name."""
        gtk_about_dialog = MagicMock()
        mock_gi_modules["gtk"].AboutDialog = MagicMock(return_value=gtk_about_dialog)

        from src.ui import compat

        with patch.object(compat, "Adw", SimpleNamespace()):
            compat.present_about_dialog(
                None,
                app_name="ClamUI",
                version="1.0.0",
                developer_name="Contributors",
                developers=["Ada https://example.com"],
                translator_credits="Bob",
            )

        gtk_about_dialog.set_authors.assert_called_once_with(["Ada https://example.com"])
        gtk_about_dialog.set_translator_credits.assert_called_once_with("Bob")
        _clear_src_modules()


class TestFileChooserFallbacks:
    def test_open_paths_dialog_uses_file_chooser_native_when_filedialog_is_unavailable(
        self, mock_gi_modules
    ):
        gtk = mock_gi_modules["gtk"]
        chooser = MagicMock()
        gtk.FileChooserNative.new.return_value = chooser
        gtk.ResponseType.ACCEPT = 1

        from src.ui import compat

        selected_paths = []
        test_filter = MagicMock()

        with patch.object(compat, "_HAS_FILE_DIALOG", False):
            compat.open_paths_dialog(
                MagicMock(),
                title="Select Files",
                on_selected=selected_paths.extend,
                multiple=True,
                filters=[test_filter],
            )

        gtk.FileChooserNative.new.assert_called_once()
        chooser.set_select_multiple.assert_called_once_with(True)
        chooser.add_filter.assert_called_once_with(test_filter)
        chooser.show.assert_called_once()

        file_one = MagicMock()
        file_one.get_path.return_value = "/tmp/file-one"
        file_two = MagicMock()
        file_two.get_path.return_value = "/tmp/file-two"
        files = MagicMock()
        files.get_n_items.return_value = 2
        files.get_item.side_effect = [file_one, file_two]
        chooser.get_files.return_value = files

        response_callback = chooser.connect.call_args[0][1]
        response_callback(chooser, gtk.ResponseType.ACCEPT)

        assert selected_paths == ["/tmp/file-one", "/tmp/file-two"]
        _clear_src_modules()

    def test_save_path_dialog_uses_file_chooser_native_when_filedialog_is_unavailable(
        self, mock_gi_modules
    ):
        gtk = mock_gi_modules["gtk"]
        chooser = MagicMock()
        gtk.FileChooserNative.new.return_value = chooser
        gtk.ResponseType.ACCEPT = 1

        from src.ui import compat

        selected_paths = []
        test_filter = MagicMock()

        with patch.object(compat, "_HAS_FILE_DIALOG", False):
            compat.save_path_dialog(
                MagicMock(),
                title="Export",
                on_selected=selected_paths.append,
                initial_name="logs.zip",
                filters=[test_filter],
            )

        chooser.set_current_name.assert_called_once_with("logs.zip")
        chooser.add_filter.assert_called_once_with(test_filter)
        chooser.show.assert_called_once()

        selected_file = MagicMock()
        selected_file.get_path.return_value = "/tmp/logs.zip"
        chooser.get_file.return_value = selected_file

        response_callback = chooser.connect.call_args[0][1]
        response_callback(chooser, gtk.ResponseType.ACCEPT)

        assert selected_paths == ["/tmp/logs.zip"]
        _clear_src_modules()
