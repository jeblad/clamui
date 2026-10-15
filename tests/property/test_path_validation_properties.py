"""Property-based tests for ``src.core.path_validation``."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

import src.core.path_validation as path_validation
from src.core.path_validation import (
    check_symlink_safety,
    format_scan_path,
    get_path_info,
    validate_dropped_files,
    validate_path,
)

pytestmark = pytest.mark.property

_PATH_COMPONENT = st.tuples(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        min_size=1,
        max_size=12,
    ),
    st.sampled_from((" ", "-", "_", "+", "$", "[", "]", "(", ")", "!", "é", "Ω", "中")),
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        min_size=0,
        max_size=12,
    ),
).map("".join)
_CONTENTS = st.binary(min_size=0, max_size=256)


def _symlink(link: Path, target: Path, *, relative: bool) -> None:
    link.symlink_to(os.path.relpath(target, link.parent) if relative else target)


@given(st.text(alphabet=" \t\r\n", max_size=10))
def test_validate_path_rejects_empty_and_whitespace(text: str) -> None:
    valid, error = validate_path(text)

    assert valid is False
    assert error is not None


@given(_PATH_COMPONENT, _CONTENTS)
def test_validate_path_accepts_existing_files_and_directories(name: str, contents: bytes) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        file_path = root / name
        directory_path = root / f"directory-{name}"
        file_path.write_bytes(contents)
        directory_path.mkdir()

        assert validate_path(str(file_path)) == (True, None)
        assert validate_path(str(directory_path)) == (True, None)


@given(_PATH_COMPONENT)
def test_validate_path_supports_relative_and_dot_segment_paths(name: str) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        nested = root / "nested"
        nested.mkdir()
        file_path = nested / name
        file_path.write_bytes(b"payload")

        with contextlib.chdir(root):
            assert validate_path(f"nested/{name}") == (True, None)
            assert validate_path(f"./nested/{name}") == (True, None)
            assert validate_path(f"nested/../nested/{name}") == (True, None)


@given(_PATH_COMPONENT)
def test_validate_path_rejects_missing_invalid_and_unreadable_inputs(name: str) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        existing = root / "existing" / name
        missing = root / "missing" / name
        existing.parent.mkdir()
        existing.write_bytes(b"payload")

        missing_valid, missing_error = validate_path(str(missing))
        nul_valid, nul_error = validate_path(f"{root}/invalid\x00{name}")
        with mock.patch.object(path_validation.os, "access", return_value=False):
            unreadable_valid, unreadable_error = validate_path(str(existing))
        with (
            mock.patch.object(path_validation, "check_symlink_safety", return_value=(True, None)),
            mock.patch.object(Path, "resolve", side_effect=OSError),
        ):
            resolution_valid, resolution_error = validate_path(str(existing))

    assert missing_valid is False
    assert missing_error is not None
    assert nul_valid is False
    assert nul_error is not None
    assert unreadable_valid is False
    assert unreadable_error is not None
    assert resolution_valid is False
    assert resolution_error is not None


@given(_PATH_COMPONENT)
def test_validate_path_rejects_directory_that_cannot_be_listed(name: str) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        directory_path = Path(temporary_directory) / name
        directory_path.mkdir()

        with mock.patch.object(Path, "iterdir", side_effect=PermissionError):
            valid, error = validate_path(str(directory_path))

    assert valid is False
    assert error is not None


@given(
    _CONTENTS,
    _PATH_COMPONENT,
    _PATH_COMPONENT,
    _PATH_COMPONENT,
    st.integers(min_value=1, max_value=3),
    st.booleans(),
)
def test_check_symlink_safety_enforces_real_links_and_policy_boundaries(
    contents: bytes,
    source_component: str,
    target_component: str,
    boundary_component: str,
    safe_chain_depth: int,
    relative_targets: bool,
) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        user_root = root / f"user-{source_component}"
        protected_root = root / f"var-{target_component}"
        var_tmp = protected_root / "tmp"
        var_home = protected_root / "home"
        protected_file = protected_root / "log" / target_component
        user_target = user_root / "targets" / target_component
        boundary_target = root / f"{protected_root.name}-backup" / target_component
        outside_user_root = root / f"{user_root.name}-backup"
        allowed_boundary_target = protected_root / f"tmp-{boundary_component}" / target_component
        for directory in (
            user_root,
            var_tmp,
            var_home,
            protected_file.parent,
            user_target.parent,
            boundary_target.parent,
            outside_user_root,
            allowed_boundary_target.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        user_target.write_bytes(contents)
        protected_file.write_bytes(contents)
        boundary_target.write_bytes(contents)
        (var_tmp / target_component).write_bytes(contents)
        (var_home / target_component).write_bytes(contents)
        allowed_boundary_target.write_bytes(contents)

        safe_links = [
            user_root / f"safe-{source_component}-{index}" for index in range(safe_chain_depth)
        ]
        for link, target in zip(safe_links, [*safe_links[1:], user_target], strict=True):
            _symlink(link, target, relative=relative_targets)

        broken_link = user_root / f"broken-{source_component}"
        protected_link = user_root / f"protected-{source_component}"
        var_tmp_link = user_root / f"var-tmp-{source_component}"
        var_home_link = user_root / f"var-home-{source_component}"
        boundary_link = user_root / f"var-boundary-{source_component}"
        allowed_boundary_link = user_root / f"tmp-boundary-{source_component}"
        outside_user_link = outside_user_root / f"protected-{source_component}"
        linked_parent = user_root / f"linked-parent-{source_component}"
        _symlink(broken_link, user_root / f"missing-{target_component}", relative=relative_targets)
        _symlink(protected_link, protected_file, relative=relative_targets)
        _symlink(var_tmp_link, var_tmp / target_component, relative=relative_targets)
        _symlink(var_home_link, var_home / target_component, relative=relative_targets)
        _symlink(boundary_link, boundary_target, relative=relative_targets)
        _symlink(
            allowed_boundary_link,
            allowed_boundary_target,
            relative=relative_targets,
        )
        _symlink(outside_user_link, protected_file, relative=relative_targets)
        _symlink(linked_parent, protected_file.parent, relative=relative_targets)

        with (
            mock.patch.object(path_validation, "_PROTECTED_SYSTEM_DIRS", (protected_root,)),
            mock.patch.object(path_validation, "_USER_WRITABLE_DIRS", (user_root, var_tmp)),
            mock.patch.object(path_validation, "_VAR_HOME_DIR", var_home),
        ):
            safe_result = check_symlink_safety(safe_links[0])
            broken_result = check_symlink_safety(broken_link)
            protected_result = check_symlink_safety(protected_link)
            var_tmp_result = check_symlink_safety(var_tmp_link)
            var_home_result = check_symlink_safety(var_home_link)
            boundary_result = check_symlink_safety(boundary_link)
            allowed_boundary_result = check_symlink_safety(allowed_boundary_link)
            outside_user_result = check_symlink_safety(outside_user_link)
            parent_escape_result = check_symlink_safety(linked_parent / protected_file.name)

    assert safe_result[0] is True
    assert safe_result[1] is not None
    assert broken_result[0] is False
    assert protected_result[0] is False
    assert var_tmp_result[0] is True
    assert var_tmp_result[1] is not None
    assert var_home_result[0] is True
    assert var_home_result[1] is not None
    assert boundary_result[0] is True
    assert allowed_boundary_result[0] is False
    assert outside_user_result[0] is True
    assert parent_escape_result[0] is False


@given(
    _PATH_COMPONENT,
    st.permutations(("file", "directory", "safe-link", "missing", "broken", "protected", "remote")),
)
def test_validate_dropped_files_preserves_every_valid_local_path_and_rejects_others(
    component: str,
    order: tuple[str, ...],
) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        user_root = root / f"user-{component}"
        protected_root = root / f"protected-{component}"
        user_root.mkdir()
        protected_root.mkdir()
        file_path = user_root / f"file-{component}"
        directory_path = user_root / f"directory-{component}"
        safe_target = user_root / f"safe-target-{component}"
        protected_target = protected_root / f"target-{component}"
        file_path.write_bytes(b"file")
        directory_path.mkdir()
        safe_target.write_bytes(b"safe")
        protected_target.write_bytes(b"protected")
        safe_link = user_root / f"safe-link-{component}"
        broken_link = user_root / f"broken-{component}"
        protected_link = user_root / f"protected-{component}"
        safe_link.symlink_to(safe_target)
        broken_link.symlink_to(user_root / f"missing-target-{component}")
        protected_link.symlink_to(protected_target)

        dropped_paths: dict[str, str | None] = {
            "file": str(file_path),
            "directory": str(directory_path),
            "safe-link": str(safe_link),
            "missing": str(user_root / f"missing-{component}"),
            "broken": str(broken_link),
            "protected": str(protected_link),
            "remote": None,
        }
        expected_paths = [
            str(Path(dropped_paths[item]).resolve())
            for item in order
            if item in {"file", "directory", "safe-link"}
        ]

        with (
            mock.patch.object(path_validation, "_PROTECTED_SYSTEM_DIRS", (protected_root,)),
            mock.patch.object(path_validation, "_USER_WRITABLE_DIRS", (user_root,)),
            mock.patch.object(path_validation, "_VAR_HOME_DIR", root / "var-home"),
        ):
            accepted, errors = validate_dropped_files([dropped_paths[item] for item in order])

    assert accepted == expected_paths
    assert len(errors) == sum(item not in {"file", "directory", "safe-link"} for item in order)


def test_validate_dropped_files_empty_list_is_rejected() -> None:
    accepted, errors = validate_dropped_files([])

    assert accepted == []
    assert len(errors) == 1


@given(_PATH_COMPONENT)
@example("edge")
def test_format_scan_path_preserves_existing_display_forms_and_empty_contract(name: str) -> None:
    home_display = f"~/{name}"
    portal_display = f"[Portal] {name}"

    empty_display = format_scan_path("")

    assert empty_display
    assert format_scan_path(None) == empty_display  # type: ignore[arg-type]
    assert format_scan_path(home_display) == home_display
    assert format_scan_path(portal_display) == portal_display


@given(st.lists(_PATH_COMPONENT, min_size=1, max_size=4))
def test_format_scan_path_preserves_generated_home_suffix(parts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        home = root / "home"
        file_path = home.joinpath(*parts)
        file_path.parent.mkdir(parents=True)
        file_path.write_bytes(b"payload")

        with mock.patch.object(Path, "home", return_value=home):
            displayed = format_scan_path(str(file_path))

    assert displayed == "~/" + "/".join(parts)


@given(_PATH_COMPONENT)
def test_format_scan_path_uses_the_portal_contract_and_resolves_nonhome_paths(name: str) -> None:
    home_portal = f"/run/user/4242/doc/abc123/Downloads/{name}"
    nonhome_portal = f"/run/flatpak/doc/def456/media/data/{name}"

    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        nonhome_file = root / name
        nonhome_file.write_bytes(b"payload")
        separate_home = root / "home"
        separate_home.mkdir()

        with mock.patch.object(Path, "home", return_value=separate_home):
            nonhome_display = format_scan_path(str(nonhome_file))

    assert format_scan_path(home_portal) == f"~/Downloads/{name}"
    assert format_scan_path(nonhome_portal) == f"/media/data/{name}"
    assert nonhome_display == str(nonhome_file.resolve())


@given(_PATH_COMPONENT)
def test_format_scan_path_falls_back_to_the_original_path_when_resolution_fails(name: str) -> None:
    path = f"/unresolvable/{name}"

    with mock.patch.object(Path, "resolve", side_effect=OSError):
        assert format_scan_path(path) == path


@given(_PATH_COMPONENT, _CONTENTS)
def test_get_path_info_reports_files_directories_missing_paths_and_symlinks(
    name: str, contents: bytes
) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        file_path = root / name
        directory_path = root / f"directory-{name}"
        missing_path = root / f"missing-{name}"
        symlink_path = root / f"file-link-{name}"
        file_path.write_bytes(contents)
        directory_path.mkdir()
        symlink_path.symlink_to(file_path)

        file_info = get_path_info(str(file_path))
        directory_info = get_path_info(str(directory_path))
        missing_info = get_path_info(str(missing_path))
        symlink_info = get_path_info(str(symlink_path))

    assert file_info["type"] == "file"
    assert file_info["exists"] is True
    assert file_info["readable"] is True
    assert file_info["size"] == len(contents)
    assert directory_info["type"] == "directory"
    assert directory_info["exists"] is True
    assert directory_info["readable"] is True
    assert directory_info["size"] is None
    assert missing_info["type"] == "unknown"
    assert missing_info["exists"] is False
    assert missing_info["readable"] is False
    assert missing_info["size"] is None
    assert {
        key: symlink_info[key] for key in ("type", "exists", "readable", "size", "display_path")
    } == {key: file_info[key] for key in ("type", "exists", "readable", "size", "display_path")}
