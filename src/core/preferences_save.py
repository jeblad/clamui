"""GTK-free Save & Apply workflow for ClamUI preferences."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .clamav_config import (
    ClamAVConfig,
    backup_config,
    validate_config,
    write_configs_with_elevation,
)
from .i18n import _


class ScheduledSettings(Protocol):
    """Durable settings operation used by the save workflow."""

    def set_many(self, updates: dict[str, Any]) -> bool: ...


class ScheduleProvisioner(Protocol):
    """Scheduler operations used after scheduled settings are durable."""

    def enable_schedule(
        self,
        *,
        frequency: str,
        time: str,
        targets: list[str],
        day_of_week: int,
        day_of_month: int,
        skip_on_battery: bool,
        auto_quarantine: bool,
    ) -> tuple[bool, str | None]: ...

    def disable_schedule(self) -> tuple[bool, str | None]: ...


class SaveStatus(Enum):
    """Truthful terminal states for the non-atomic save workflow."""

    SAVED = "saved"
    NO_CHANGES = "no_changes"
    FAILED = "failed"
    PARTIALLY_APPLIED = "partially_applied"


class DurableGroup(Enum):
    """Groups that are known durable when a workflow result is returned."""

    CLAMAV_CONFIGS = "clamav_configs"
    SCHEDULED_PREFERENCES = "scheduled_preferences"


@dataclass(frozen=True)
class PreferenceSaveState:
    """Window-owned config state captured once at Save & Apply click time."""

    freshclam_config: ClamAVConfig | None
    clamd_config: ClamAVConfig | None
    freshclam_conf_path: str
    clamd_conf_path: str
    clamd_available: bool


@dataclass(frozen=True)
class PreferenceSaveRequest:
    """Click-time state and collected values needed for one save operation."""

    state: PreferenceSaveState
    freshclam_updates: dict[str, Any]
    clamd_updates: dict[str, Any]
    onaccess_updates: dict[str, Any]
    scheduled_updates: dict[str, Any]


@dataclass(frozen=True)
class PreparedPreferenceSave:
    """Validated proposals detached from GTK state and ready for worker I/O."""

    freshclam_conf_path: str
    clamd_conf_path: str
    clamd_available: bool
    freshclam_proposal: ClamAVConfig | None
    clamd_proposal: ClamAVConfig | None
    scheduled_updates: dict[str, Any]


@dataclass(frozen=True)
class PreferenceSaveResult:
    """Durable outcome and configs to commit on the GTK main thread."""

    status: SaveStatus
    freshclam_config: ClamAVConfig | None = None
    clamd_config: ClamAVConfig | None = None
    durable_groups: tuple[DurableGroup, ...] = ()
    error: str | None = None
    config_write_warning: str | None = None


class PreferenceSaveValidationError(Exception):
    """A proposal could not be created or validated before worker execution."""

    def __init__(self, title: str, message: str) -> None:
        super().__init__(message)
        self.title = title
        self.message = message


def _copy_config(config: ClamAVConfig) -> ClamAVConfig:
    """Make the one independent working copy needed for a config proposal."""
    return ClamAVConfig(
        file_path=config.file_path,
        values=copy.deepcopy(config.values),
        raw_lines=list(config.raw_lines),
    )


def _apply_updates(config: ClamAVConfig, updates: dict[str, Any]) -> None:
    """Apply form values while preserving ClamAV multi-value semantics."""
    for key, value in updates.items():
        if isinstance(value, list):
            config.remove_key(key)
            for item in value:
                config.add_value(key, item)
        else:
            config.set_value(key, value)


def _proposed_config(config: ClamAVConfig, updates: tuple[dict[str, Any], ...]) -> ClamAVConfig:
    """Return the working copy used for validation and unchanged filtering."""
    proposal = _copy_config(config)
    for group in updates:
        _apply_updates(proposal, group)
    return proposal


def _changed_proposal(config: ClamAVConfig, proposal: ClamAVConfig) -> ClamAVConfig | None:
    """Retain a validated proposal only when it differs from its loaded config."""
    return proposal if proposal.to_string() != config.to_string() else None


def _validate_proposal(config: ClamAVConfig) -> None:
    """Raise the stable UI-facing validation failure for a proposed config."""
    valid, errors = validate_config(config)
    if not valid:
        raise PreferenceSaveValidationError(_("Validation Error"), "\n".join(errors))


def prepare_preference_save(request: PreferenceSaveRequest) -> PreparedPreferenceSave:
    """Build and validate click-time proposals without performing I/O."""
    freshclam_proposal = None
    if request.freshclam_updates:
        if request.state.freshclam_config is None:
            raise PreferenceSaveValidationError(
                _("Configuration Error"),
                _(
                    "Cannot save freshclam settings: Configuration failed to load.\n\n"
                    "This may be due to:\n"
                    "- Missing configuration file\n"
                    "- Insufficient permissions\n"
                    "- Disk space issues (Flatpak)\n\n"
                    "Check the application logs for details."
                ),
            )
        freshclam_candidate = _proposed_config(
            request.state.freshclam_config, (request.freshclam_updates,)
        )
        _validate_proposal(freshclam_candidate)
        freshclam_proposal = _changed_proposal(request.state.freshclam_config, freshclam_candidate)

    clamd_proposal = None
    clamd_update_groups = tuple(
        updates for updates in (request.clamd_updates, request.onaccess_updates) if updates
    )
    if clamd_update_groups and request.state.clamd_available:
        if request.state.clamd_config is None:
            raise PreferenceSaveValidationError(
                _("Configuration Error"),
                _(
                    "Cannot save clamd settings: Configuration failed to load.\n\n"
                    "Check that {path} exists and is readable."
                ).format(path=request.state.clamd_conf_path),
            )
        clamd_candidate = _proposed_config(request.state.clamd_config, clamd_update_groups)
        _validate_proposal(clamd_candidate)
        clamd_proposal = _changed_proposal(request.state.clamd_config, clamd_candidate)

    return PreparedPreferenceSave(
        freshclam_conf_path=request.state.freshclam_conf_path,
        clamd_conf_path=request.state.clamd_conf_path,
        clamd_available=request.state.clamd_available,
        freshclam_proposal=freshclam_proposal,
        clamd_proposal=clamd_proposal,
        scheduled_updates=copy.deepcopy(request.scheduled_updates),
    )


def _failure_result(
    *,
    error: str,
    freshclam_config: ClamAVConfig | None,
    clamd_config: ClamAVConfig | None,
    durable_groups: list[DurableGroup],
    config_write_warning: str | None,
) -> PreferenceSaveResult:
    return PreferenceSaveResult(
        status=SaveStatus.PARTIALLY_APPLIED if durable_groups else SaveStatus.FAILED,
        freshclam_config=freshclam_config,
        clamd_config=clamd_config,
        durable_groups=tuple(durable_groups),
        error=error,
        config_write_warning=config_write_warning,
    )


def apply_preference_save(
    prepared: PreparedPreferenceSave,
    settings: ScheduledSettings | None,
    scheduler: ScheduleProvisioner | None,
) -> PreferenceSaveResult:
    """Persist prepared proposals in their required non-atomic ordering.

    The returned configs are only those whose host write completed successfully.
    Callers must commit them before presenting any later partial failure.
    """
    durable_groups: list[DurableGroup] = []
    committed_freshclam = None
    committed_clamd = None
    config_write_warning = None

    try:
        backup_config(prepared.freshclam_conf_path)
        if prepared.clamd_available:
            backup_config(prepared.clamd_conf_path)

        configs_to_write = [
            config
            for config in (prepared.freshclam_proposal, prepared.clamd_proposal)
            if config is not None
        ]
        if configs_to_write:
            success, error = write_configs_with_elevation(configs_to_write)
            if not success:
                return _failure_result(
                    error=_("Failed to save configuration files: {error}").format(error=error),
                    freshclam_config=None,
                    clamd_config=None,
                    durable_groups=durable_groups,
                    config_write_warning=None,
                )
            committed_freshclam = prepared.freshclam_proposal
            committed_clamd = prepared.clamd_proposal
            durable_groups.append(DurableGroup.CLAMAV_CONFIGS)
            config_write_warning = error

        if prepared.scheduled_updates:
            if settings is None or not settings.set_many(prepared.scheduled_updates):
                return _failure_result(
                    error=_("Failed to save scheduled scan settings"),
                    freshclam_config=committed_freshclam,
                    clamd_config=committed_clamd,
                    durable_groups=durable_groups,
                    config_write_warning=config_write_warning,
                )
            durable_groups.append(DurableGroup.SCHEDULED_PREFERENCES)

            if scheduler is None:
                return _failure_result(
                    error=_("Failed to apply scheduled scans: scheduler unavailable"),
                    freshclam_config=committed_freshclam,
                    clamd_config=committed_clamd,
                    durable_groups=durable_groups,
                    config_write_warning=config_write_warning,
                )

            if prepared.scheduled_updates.get("scheduled_scans_enabled"):
                success, error = scheduler.enable_schedule(
                    frequency=prepared.scheduled_updates.get("schedule_frequency", "daily"),
                    time=prepared.scheduled_updates.get("schedule_time", "02:00"),
                    targets=prepared.scheduled_updates.get("schedule_targets", []),
                    day_of_week=prepared.scheduled_updates.get("schedule_day_of_week", 0),
                    day_of_month=prepared.scheduled_updates.get("schedule_day_of_month", 1),
                    skip_on_battery=prepared.scheduled_updates.get(
                        "schedule_skip_on_battery", True
                    ),
                    auto_quarantine=prepared.scheduled_updates.get(
                        "schedule_auto_quarantine", False
                    ),
                )
                action = _("enable")
            else:
                success, error = scheduler.disable_schedule()
                action = _("disable")
            if not success:
                return _failure_result(
                    error=_("Failed to {action} scheduled scans: {error}").format(
                        action=action, error=error
                    ),
                    freshclam_config=committed_freshclam,
                    clamd_config=committed_clamd,
                    durable_groups=durable_groups,
                    config_write_warning=config_write_warning,
                )
    except Exception as error:
        return _failure_result(
            error=str(error),
            freshclam_config=committed_freshclam,
            clamd_config=committed_clamd,
            durable_groups=durable_groups,
            config_write_warning=config_write_warning,
        )

    if not durable_groups:
        return PreferenceSaveResult(status=SaveStatus.NO_CHANGES)
    return PreferenceSaveResult(
        status=SaveStatus.SAVED,
        freshclam_config=committed_freshclam,
        clamd_config=committed_clamd,
        durable_groups=tuple(durable_groups),
        config_write_warning=config_write_warning,
    )
