# ClamUI Save & Apply Page
"""
Save & Apply preference page for configuration persistence.

This module provides the SavePage class which handles saving all
preference changes to ClamAV configuration files and ClamUI settings.
"""

import threading
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from ...core.flatpak import is_flatpak
from ...core.i18n import _
from ...core.preferences_save import (
    DurableGroup,
    PreferenceSaveRequest,
    PreferenceSaveResult,
    PreferenceSaveState,
    PreferenceSaveValidationError,
    PreparedPreferenceSave,
    SaveStatus,
    prepare_preference_save,
)
from ...core.privileged_helper import (
    PrivilegedHelperState,
    PrivilegedHelperStatus,
    get_privileged_helper_status,
)
from ..compat import create_toolbar_view, safe_set_subtitle_lines, safe_set_title_lines
from ..privileged_helper_dialog import present_privileged_helper_dialog
from ..utils import resolve_icon_name
from .base import PreferencesPageMixin
from .database_page import DatabasePage
from .onaccess_page import OnAccessPage
from .scanner_page import ScannerPage
from .scheduled_page import ScheduledPage


class SavePage(PreferencesPageMixin):
    """
    GTK adapter for collecting and rendering the Save & Apply workflow.

    The page owns widget collection, the background-thread hand-off, and
    main-thread presentation. Proposal validation and persistence ordering are
    owned by :mod:`core.preferences_save`.
    """

    def __init__(
        self,
        window,
        state_provider: Callable[[], PreferenceSaveState],
        workflow_runner: Callable[[PreparedPreferenceSave], PreferenceSaveResult],
        result_handler: Callable[[PreferenceSaveResult, PreferenceSaveState], None],
        freshclam_widgets: dict,
        clamd_widgets: dict,
        onaccess_widgets: dict,
        scheduled_widgets: dict,
    ):
        """
        Initialize the GTK adapter for the Save & Apply workflow.

        ``state_provider`` captures window-owned config state on the GTK
        thread. ``result_handler`` receives that captured state with the
        durable result so the window only commits configs for its still-selected
        paths before this page renders the workflow outcome.
        """
        self._window = window
        self._state_provider = state_provider
        self._workflow_runner = workflow_runner
        self._result_handler = result_handler
        # Store widget dictionaries for click-time data collection.
        self._freshclam_widgets = freshclam_widgets
        self._clamd_widgets = clamd_widgets
        self._onaccess_widgets = onaccess_widgets
        self._scheduled_widgets = scheduled_widgets

        # Track saving state.
        self._is_saving = False

        # Store references for the Flatpak privileged-helper status row.
        self._privileged_helper_row = None
        self._privileged_helper_icon = None
        self._privileged_helper_button = None
        self._privileged_helper_status: PrivilegedHelperStatus | None = None
        self._privileged_helper_status_thread = None

        # Store reference to save button.
        self._save_button = None

    def _show_error_dialog(self, title: str, message: str):
        """
        Show an error dialog to the user.

        Overrides PreferencesPageMixin to use self._window as parent
        since SavePage is not a GTK widget.

        Args:
            title: Dialog title
            message: Error message text
        """
        self._show_simple_dialog(title, message)

    def _show_success_dialog(self, title: str, message: str):
        """
        Show a success dialog to the user.

        Overrides PreferencesPageMixin to use self._window as parent
        since SavePage is not a GTK widget.

        Args:
            title: Dialog title
            message: Success message text
        """
        self._show_simple_dialog(title, message)

    def _show_simple_dialog(self, title: str, message: str):
        """
        Show a simple message dialog with an OK button.

        Uses Adw.Window for compatibility with libadwaita < 1.5.

        Args:
            title: Dialog title/heading
            message: Message body text
        """
        dialog = Adw.Window()
        dialog.set_title(title)
        dialog.set_default_size(350, -1)
        dialog.set_modal(True)
        dialog.set_deletable(True)
        dialog.set_transient_for(self._window)

        # Create content
        toolbar_view = create_toolbar_view()
        header_bar = Adw.HeaderBar()
        toolbar_view.add_top_bar(header_bar)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_start(24)
        content_box.set_margin_end(24)
        content_box.set_margin_top(12)
        content_box.set_margin_bottom(24)

        # Message label
        label = Gtk.Label()
        label.set_text(message)
        label.set_wrap(True)
        label.set_xalign(0)
        content_box.append(label)

        # OK button
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        button_box.set_halign(Gtk.Align.END)
        button_box.set_margin_top(12)

        ok_button = Gtk.Button(label=_("OK"))
        ok_button.add_css_class("suggested-action")
        ok_button.connect("clicked", lambda btn: dialog.close())
        button_box.append(ok_button)

        content_box.append(button_box)
        toolbar_view.set_content(content_box)
        dialog.set_content(toolbar_view)

        dialog.present()

    def create_page(self) -> Adw.PreferencesPage:
        """
        Create the Save & Apply preference page.

        This page provides information about save behavior and a button
        to save all configuration changes.

        Returns:
            Configured Adw.PreferencesPage ready to be added to preferences window
        """
        page = Adw.PreferencesPage(
            title=_("Save & Apply"),
            icon_name=resolve_icon_name("document-save-symbolic"),
        )

        # Information banner explaining what needs to be saved
        info_group = Adw.PreferencesGroup()
        info_group.set_title(_("Save Behavior"))

        # Auto-save settings info row
        auto_save_row = Adw.ActionRow()
        auto_save_row.set_title(_("Auto-Saved"))
        auto_save_row.set_subtitle(_("Scan Backend, Exclusions"))
        auto_save_icon = Gtk.Image.new_from_icon_name(resolve_icon_name("emblem-default-symbolic"))
        auto_save_icon.add_css_class("success")
        auto_save_row.add_prefix(auto_save_icon)
        info_group.add(auto_save_row)

        if is_flatpak():
            self._create_privileged_helper_row(info_group)
            self._refresh_privileged_helper_status()

        # System configuration writes from Flatpak always require the matching
        # host helper. Its display status is checked asynchronously above; the
        # save path remains responsible for failing closed if it is unavailable.
        from ...core.privileged_paths import is_running_as_root

        manual_save_row = Adw.ActionRow()
        manual_save_row.set_title(_("Manual Save Required"))
        safe_set_title_lines(manual_save_row, 1)
        if is_flatpak():
            manual_save_row.set_subtitle(
                _(
                    "Database Updates, Scanner, On-Access, Scheduled Scans. "
                    "A matching host privileged helper is required; authorization "
                    "occurs only when the helper is available."
                )
            )
            manual_icon_name = "system-lock-screen-symbolic"
            manual_icon_css = "warning"
        elif is_running_as_root():
            manual_save_row.set_subtitle(
                _("Database Updates, Scanner, On-Access, Scheduled Scans.")
            )
            manual_icon_name = "emblem-default-symbolic"
            manual_icon_css = "success"
        else:
            manual_save_row.set_subtitle(
                _(
                    "Database Updates, Scanner, On-Access, Scheduled Scans. "
                    "When needed, you will be asked for administrator permission once."
                )
            )
            manual_icon_name = "system-lock-screen-symbolic"
            manual_icon_css = "warning"
        safe_set_subtitle_lines(manual_save_row, 2)
        lock_icon = Gtk.Image.new_from_icon_name(resolve_icon_name(manual_icon_name))
        lock_icon.add_css_class(manual_icon_css)
        manual_save_row.add_prefix(lock_icon)
        info_group.add(manual_save_row)

        page.add(info_group)

        # Save & apply button group
        button_group = Adw.PreferencesGroup()
        button_group.set_title(_("Apply Configuration"))

        # Save button row - using ActionRow to properly contain the button
        save_action_row = Adw.ActionRow()
        save_action_row.set_title(_("Save Configuration"))
        save_action_row.set_subtitle(_("Apply all pending changes at once."))
        safe_set_subtitle_lines(save_action_row, 1)

        # Create the save button
        self._save_button = Gtk.Button()
        self._save_button.set_label(_("Save & Apply"))
        self._save_button.add_css_class("suggested-action")
        self._save_button.set_valign(Gtk.Align.CENTER)
        self._save_button.connect("clicked", self._on_save_clicked)

        # Add button as suffix to the row
        save_action_row.add_suffix(self._save_button)

        button_group.add(save_action_row)
        page.add(button_group)

        return page

    def _create_privileged_helper_row(self, group: Adw.PreferencesGroup) -> None:
        """Add the Flatpak host-helper status and installation controls."""
        self._privileged_helper_row = Adw.ActionRow()
        self._privileged_helper_row.set_title(_("Privileged Helper"))
        self._privileged_helper_row.set_subtitle(
            _("Checking whether the matching host helper is installed…")
        )
        safe_set_subtitle_lines(self._privileged_helper_row, 2)

        self._privileged_helper_icon = Gtk.Image.new_from_icon_name(
            resolve_icon_name("emblem-synchronizing-symbolic")
        )
        self._privileged_helper_icon.add_css_class("dim-label")
        self._privileged_helper_row.add_prefix(self._privileged_helper_icon)

        self._privileged_helper_button = Gtk.Button()
        self._privileged_helper_button.set_label(_("Install Helper"))
        self._privileged_helper_button.set_valign(Gtk.Align.CENTER)
        self._privileged_helper_button.set_sensitive(False)
        self._privileged_helper_button.connect(
            "clicked", self._on_install_privileged_helper_clicked
        )
        self._privileged_helper_row.add_suffix(self._privileged_helper_button)
        group.add(self._privileged_helper_row)

    def _refresh_privileged_helper_status(self) -> None:
        """Probe helper availability without blocking the GTK main thread."""
        status_thread = threading.Thread(target=self._probe_privileged_helper_status)
        status_thread.daemon = True
        self._privileged_helper_status_thread = status_thread
        status_thread.start()

    def _probe_privileged_helper_status(self) -> None:
        """Fetch the host-helper status, then hand rendering to GTK's main loop."""
        status = get_privileged_helper_status()
        GLib.idle_add(self._render_privileged_helper_status, status)

    def _render_privileged_helper_status(self, status: PrivilegedHelperStatus) -> None:
        """Render a helper status on the GTK main thread."""
        if (
            self._privileged_helper_row is None
            or self._privileged_helper_icon is None
            or self._privileged_helper_button is None
        ):
            return

        self._privileged_helper_status = status
        self._privileged_helper_icon.remove_css_class("success")
        self._privileged_helper_icon.remove_css_class("warning")
        self._privileged_helper_icon.remove_css_class("dim-label")

        if status.state is PrivilegedHelperState.INSTALLED:
            self._privileged_helper_row.set_subtitle(
                _("Installed: {package} {version}.").format(
                    package=status.package_name, version=status.version
                )
            )
            self._privileged_helper_icon.set_from_icon_name(
                resolve_icon_name("emblem-default-symbolic")
            )
            self._privileged_helper_icon.add_css_class("success")
            self._privileged_helper_button.set_visible(False)
            self._privileged_helper_button.set_sensitive(False)
            return

        if status.state is PrivilegedHelperState.INSTALLABLE:
            self._privileged_helper_row.set_subtitle(
                status.detail or _("A matching host privileged helper can be installed.")
            )
            self._privileged_helper_icon.set_from_icon_name(
                resolve_icon_name("dialog-warning-symbolic")
            )
            self._privileged_helper_icon.add_css_class("warning")
            self._privileged_helper_button.set_visible(True)
            self._privileged_helper_button.set_sensitive(True)
            return

        if status.state is PrivilegedHelperState.UNSUPPORTED:
            self._privileged_helper_row.set_subtitle(
                status.detail or _("Automatic installation is unavailable on this host.")
            )
        else:
            self._privileged_helper_row.set_subtitle(
                status.detail or _("No host privileged helper is required.")
            )
        self._privileged_helper_icon.set_from_icon_name(
            resolve_icon_name("dialog-information-symbolic")
        )
        self._privileged_helper_icon.add_css_class("dim-label")
        self._privileged_helper_button.set_visible(False)
        self._privileged_helper_button.set_sensitive(False)

    def _on_install_privileged_helper_clicked(self, _button: Gtk.Button) -> None:
        """Present the helper installer after the asynchronous status check."""
        if not self._privileged_helper_status or not self._privileged_helper_status.can_install:
            return

        present_privileged_helper_dialog(
            self._window, on_installed=self._on_privileged_helper_installed
        )

    def _on_privileged_helper_installed(self) -> None:
        """Refresh the status after the installer succeeds."""
        self._refresh_privileged_helper_status()

    def _on_save_clicked(self, button: Gtk.Button):
        """Collect values and start one detached preference-save workflow."""
        if self._is_saving:
            return

        self._is_saving = True
        button.set_sensitive(False)

        state = self._state_provider()
        request = PreferenceSaveRequest(
            state=state,
            freshclam_updates=DatabasePage.collect_data(self._freshclam_widgets),
            clamd_updates=ScannerPage.collect_data(self._clamd_widgets, state.clamd_available),
            onaccess_updates=OnAccessPage.collect_data(
                self._onaccess_widgets, state.clamd_available
            ),
            scheduled_updates=ScheduledPage.collect_data(self._scheduled_widgets),
        )
        try:
            prepared = prepare_preference_save(request)
        except PreferenceSaveValidationError as error:
            self._show_error_dialog(error.title, error.message)
            self._is_saving = False
            button.set_sensitive(True)
            return

        save_thread = threading.Thread(
            target=self._save_prepared,
            args=(prepared, state, button),
            daemon=True,
        )
        save_thread.start()

    def _save_prepared(
        self,
        prepared: PreparedPreferenceSave,
        saved_state: PreferenceSaveState,
        button: Gtk.Button,
    ) -> None:
        """Run persistence without accessing GTK widgets or window state."""
        result = self._workflow_runner(prepared)
        GLib.idle_add(self._complete_save, result, saved_state, button)

    def _complete_save(
        self,
        result: PreferenceSaveResult,
        saved_state: PreferenceSaveState,
        button: Gtk.Button,
    ) -> bool:
        """Commit durable state and render the terminal result on GTK's thread."""
        self._result_handler(result, saved_state)

        if result.status is SaveStatus.SAVED:
            if result.config_write_warning is not None:
                self._show_success_dialog(
                    _("Configuration Saved with Warning"),
                    _("Configuration saved with a warning:\n\n{warning}").format(
                        warning=result.config_write_warning
                    ),
                )
            else:
                self._show_success_dialog(
                    _("Configuration Saved"),
                    _("Configuration saved. Active ClamAV services were restarted where needed."),
                )
        elif result.status is SaveStatus.NO_CHANGES:
            self._show_success_dialog(
                _("No Changes to Apply"),
                _(
                    "No configuration changes were detected, so nothing was saved. "
                    "Open a settings page and modify a value before saving."
                ),
            )
        elif result.status is SaveStatus.PARTIALLY_APPLIED:
            group_names = {
                DurableGroup.CLAMAV_CONFIGS: _("ClamAV configuration files"),
                DurableGroup.SCHEDULED_PREFERENCES: _("Scheduled scan preferences"),
            }
            self._show_error_dialog(
                _("Changes Partially Applied"),
                _(
                    "The following changes were saved before another change failed:\n"
                    "{saved_groups}\n\n"
                    "Error: {error}\n\n"
                    "Review your settings and save again."
                ).format(
                    saved_groups=", ".join(group_names[group] for group in result.durable_groups),
                    error=result.error,
                ),
            )
        else:
            self._show_error_dialog(_("Save Failed"), result.error or _("Unknown error"))

        self._is_saving = False
        button.set_sensitive(True)
        return False
