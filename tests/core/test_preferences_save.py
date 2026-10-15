"""Behavior tests for the GTK-free preferences save workflow."""

from pathlib import Path
from unittest import mock

import pytest

from src.core.clamav_config import (
    ClamAVConfig,
    ClamAVConfigValue,
    write_configs_with_elevation,
)
from src.core.preferences_save import (
    DurableGroup,
    PreferenceSaveRequest,
    PreferenceSaveState,
    PreferenceSaveValidationError,
    SaveStatus,
    apply_preference_save,
    prepare_preference_save,
)


def _config(path: Path, key: str, value: str) -> ClamAVConfig:
    path.write_text(f"{key} {value}\n", encoding="utf-8")
    return ClamAVConfig(
        file_path=path,
        values={key: [ClamAVConfigValue(value=value, line_number=1)]},
        raw_lines=[f"{key} {value}\n"],
    )


def _request(
    *,
    freshclam: ClamAVConfig | None = None,
    clamd: ClamAVConfig | None = None,
    clamd_available: bool = True,
    freshclam_updates: dict | None = None,
    clamd_updates: dict | None = None,
    onaccess_updates: dict | None = None,
    scheduled_updates: dict | None = None,
    freshclam_path: str = "/tmp/freshclam.conf",
    clamd_path: str = "/tmp/clamd.conf",
) -> PreferenceSaveRequest:
    return PreferenceSaveRequest(
        state=PreferenceSaveState(
            freshclam_config=freshclam,
            clamd_config=clamd,
            freshclam_conf_path=freshclam_path,
            clamd_conf_path=clamd_path,
            clamd_available=clamd_available,
        ),
        freshclam_updates=freshclam_updates or {},
        clamd_updates=clamd_updates or {},
        onaccess_updates=onaccess_updates or {},
        scheduled_updates=scheduled_updates or {},
    )


@pytest.mark.parametrize(
    ("config_name", "option", "invalid_value", "freshclam"),
    [
        ("freshclam.conf", "Checks", "51", True),
        ("clamd.conf", "MaxRecursion", "101", False),
    ],
)
def test_invalid_updates_do_not_mutate_or_persist_loaded_config(
    tmp_path, config_name, option, invalid_value, freshclam
):
    config_path = tmp_path / config_name
    live = _config(config_path, option, "12" if freshclam else "17")
    before = config_path.read_text(encoding="utf-8")

    request = _request(
        freshclam=live if freshclam else None,
        clamd=None if freshclam else live,
        clamd_available=not freshclam,
        freshclam_updates={option: invalid_value} if freshclam else {},
        clamd_updates={} if freshclam else {option: invalid_value},
        freshclam_path=str(config_path) if freshclam else str(tmp_path / "freshclam.conf"),
        clamd_path=str(config_path) if not freshclam else str(tmp_path / "clamd.conf"),
    )

    with pytest.raises(PreferenceSaveValidationError) as error:
        prepare_preference_save(request)

    assert option in error.value.message
    assert live.get_value(option) == ("12" if freshclam else "17")
    assert live.to_string() == before
    assert config_path.read_text(encoding="utf-8") == before
    assert list(tmp_path.glob("*.bak.*")) == []


def test_repairing_stale_invalid_config_writes_corrected_value(tmp_path):
    config_path = tmp_path / "freshclam.conf"
    live = _config(config_path, "Checks", "51")

    prepared = prepare_preference_save(
        _request(
            freshclam=live,
            freshclam_updates={"Checks": "12"},
            freshclam_path=str(config_path),
            clamd_available=False,
        )
    )
    result = apply_preference_save(prepared, None, None)

    assert result.status is SaveStatus.SAVED
    assert result.freshclam_config is prepared.freshclam_proposal
    assert live.get_value("Checks") == "51"
    assert config_path.read_text(encoding="utf-8") == "Checks 12\n"


def test_failed_write_leaves_live_config_unchanged_and_corrected_retry_persists(tmp_path):
    config_path = tmp_path / "freshclam.conf"
    live = _config(config_path, "Checks", "12")
    failed_prepared = prepare_preference_save(
        _request(
            freshclam=live,
            freshclam_updates={"Checks": "24"},
            freshclam_path=str(config_path),
            clamd_available=False,
        )
    )

    with mock.patch(
        "src.core.preferences_save.write_configs_with_elevation",
        return_value=(False, "host writer unavailable"),
    ):
        failed_result = apply_preference_save(failed_prepared, None, None)

    assert failed_result.status is SaveStatus.FAILED
    assert failed_result.freshclam_config is None
    assert live.get_value("Checks") == "12"
    assert config_path.read_text(encoding="utf-8") == "Checks 12\n"

    retry_prepared = prepare_preference_save(
        _request(
            freshclam=live,
            freshclam_updates={"Checks": "36"},
            freshclam_path=str(config_path),
            clamd_available=False,
        )
    )
    retry_result = apply_preference_save(retry_prepared, None, None)

    assert retry_result.status is SaveStatus.SAVED
    assert retry_result.freshclam_config is retry_prepared.freshclam_proposal
    assert live.get_value("Checks") == "12"
    assert config_path.read_text(encoding="utf-8") == "Checks 36\n"


def test_settings_persistence_failure_skips_scheduler_and_retains_durable_config(tmp_path):
    config_path = tmp_path / "freshclam.conf"
    live = _config(config_path, "Checks", "12")
    prepared = prepare_preference_save(
        _request(
            freshclam=live,
            freshclam_updates={"Checks": "24"},
            scheduled_updates={"scheduled_scans_enabled": True},
            freshclam_path=str(config_path),
            clamd_available=False,
        )
    )
    settings = mock.MagicMock()
    settings.set_many.return_value = False
    scheduler = mock.MagicMock()

    result = apply_preference_save(prepared, settings, scheduler)

    assert result.status is SaveStatus.PARTIALLY_APPLIED
    assert result.freshclam_config is prepared.freshclam_proposal
    assert result.durable_groups == (DurableGroup.CLAMAV_CONFIGS,)
    assert config_path.read_text(encoding="utf-8") == "Checks 24\n"
    scheduler.enable_schedule.assert_not_called()
    scheduler.disable_schedule.assert_not_called()


def test_config_write_warning_keeps_real_persisted_config_committable(tmp_path):
    config_path = tmp_path / "freshclam.conf"
    live = _config(config_path, "Checks", "12")
    prepared = prepare_preference_save(
        _request(
            freshclam=live,
            freshclam_updates={"Checks": "24"},
            freshclam_path=str(config_path),
            clamd_available=False,
        )
    )

    def write_with_cleanup_warning(configs):
        success, error = write_configs_with_elevation(configs)
        assert success is True
        assert error is None
        return (True, "Staging cleanup was delayed")

    with mock.patch(
        "src.core.preferences_save.write_configs_with_elevation",
        side_effect=write_with_cleanup_warning,
    ):
        result = apply_preference_save(prepared, None, None)

    assert result.status is SaveStatus.SAVED
    assert result.freshclam_config is prepared.freshclam_proposal
    assert result.durable_groups == (DurableGroup.CLAMAV_CONFIGS,)
    assert result.config_write_warning == "Staging cleanup was delayed"
    assert config_path.read_text(encoding="utf-8") == "Checks 24\n"
