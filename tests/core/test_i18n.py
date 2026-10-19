"""Tests for the i18n (internationalization) module."""

import gettext
import importlib
import os
import struct
from pathlib import Path
from unittest import mock

import pytest


def _write_mo(path: Path, catalog: dict[str, str]) -> None:
    """Write a minimal GNU gettext catalog for translation behavior tests."""
    messages = sorted(
        (message.encode(), translation.encode()) for message, translation in catalog.items()
    )
    originals = b""
    translations = b""
    original_offsets: list[tuple[int, int]] = []
    translation_offsets: list[tuple[int, int]] = []

    for message, translation in messages:
        original_offsets.append((len(message), len(originals)))
        translation_offsets.append((len(translation), len(translations)))
        originals += message + b"\0"
        translations += translation + b"\0"

    count = len(messages)
    original_table_offset = 7 * 4
    translation_table_offset = original_table_offset + count * 8
    strings_offset = translation_table_offset + count * 8
    translation_offset = strings_offset + len(originals)

    header = struct.pack(
        "<7I",
        0x950412DE,
        0,
        count,
        original_table_offset,
        translation_table_offset,
        0,
        translation_offset + len(translations),
    )
    original_table = b"".join(
        struct.pack("<2I", length, strings_offset + offset) for length, offset in original_offsets
    )
    translation_table = b"".join(
        struct.pack("<2I", length, translation_offset + offset)
        for length, offset in translation_offsets
    )

    path.parent.mkdir(parents=True)
    path.write_bytes(header + original_table + translation_table + originals + translations)


@pytest.fixture
def german_i18n(monkeypatch, tmp_path):
    """Load i18n against an isolated catalog with a startup language override."""
    appdir = tmp_path / "AppDir"
    _write_mo(
        appdir / "usr" / "share" / "locale" / "de" / "LC_MESSAGES" / "clamui.mo",
        {
            "": "Language: de\nPlural-Forms: nplurals=2; plural=(n != 1);\n",
            "Scan Complete": "Scan abgeschlossen",
            "{n} file\0{n} files": "{n} Datei\0{n} Dateien",
            "menu\4File": "Datei",
        },
    )

    from src.core import i18n

    with monkeypatch.context() as environment:
        environment.setenv("APPDIR", str(appdir))
        environment.setenv("LANGUAGE", "de")
        yield importlib.reload(i18n)

    importlib.reload(i18n)


@pytest.fixture
def fallback_i18n(monkeypatch, tmp_path):
    """Load i18n with no matching catalog under a startup language override."""
    appdir = tmp_path / "AppDir"
    (appdir / "usr" / "share" / "locale").mkdir(parents=True)

    from src.core import i18n

    with monkeypatch.context() as environment:
        environment.setenv("APPDIR", str(appdir))
        environment.setenv("LANGUAGE", "de")
        yield importlib.reload(i18n)

    importlib.reload(i18n)


class TestGettext:
    """Test translation behavior through a real isolated gettext catalog."""

    def test_startup_language_override_loads_translation(self, german_i18n):
        """LANGUAGE selected before import determines the process catalog."""
        assert german_i18n._("Scan Complete") == "Scan abgeschlossen"

    def test_catalog_remains_fixed_after_startup(self, german_i18n, monkeypatch):
        """Changing LANGUAGE after import does not switch the process catalog."""
        with monkeypatch.context() as environment:
            environment.setenv("LANGUAGE", "C")
            assert german_i18n._("Scan Complete") == "Scan abgeschlossen"

    def test_catalog_preserves_plural_and_context_translation(self, german_i18n):
        """Bound translation methods retain gettext plural and context behavior."""
        assert german_i18n.ngettext("{n} file", "{n} files", 1) == "{n} Datei"
        assert german_i18n.ngettext("{n} file", "{n} files", 2) == "{n} Dateien"
        assert german_i18n.pgettext("menu", "File") == "Datei"

    def test_missing_catalog_falls_back_to_source(self, fallback_i18n):
        """A missing catalog falls back without raising a lookup error."""
        assert fallback_i18n._("Not in the catalog") == "Not in the catalog"

    def test_loaded_catalog_does_not_resolve_files_per_lookup(self, german_i18n):
        """Translated rows reuse the catalog selected at module import."""
        with mock.patch.object(
            gettext, "find", side_effect=AssertionError("unexpected catalog lookup")
        ):
            assert [german_i18n._("Scan Complete") for _ in range(3)] == [
                "Scan abgeschlossen",
                "Scan abgeschlossen",
                "Scan abgeschlossen",
            ]

    def test_n_underscore_identity(self):
        """N_() returns the string unchanged for deferred translation."""
        from src.core.i18n import N_

        text = "Test String"
        assert N_(text) is text


class TestLocaleDirDetection:
    """Test locale directory detection for different runtime contexts."""

    def test_appimage_locale_dir(self, tmp_path):
        """Detects locale dir in AppImage context."""
        from src.core import i18n

        appdir = str(tmp_path / "AppDir")
        locale_dir = os.path.join(appdir, "usr", "share", "locale")
        os.makedirs(locale_dir)

        with mock.patch.dict(os.environ, {"APPDIR": appdir}):
            result = i18n._get_locale_dir()
            assert result == locale_dir

    def test_flatpak_locale_dir(self):
        """Detects locale dir in Flatpak context."""
        from src.core import i18n

        flatpak_locale = "/app/share/locale"

        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("os.path.exists") as mock_exists,
            mock.patch("os.path.isdir") as mock_isdir,
        ):
            # Remove APPDIR to skip AppImage check
            os.environ.pop("APPDIR", None)

            mock_exists.side_effect = lambda path: path == "/.flatpak-info"
            mock_isdir.side_effect = lambda path: path == flatpak_locale

            result = i18n._get_locale_dir()
            assert result == flatpak_locale

    def test_dev_locale_dir(self, tmp_path):
        """Detects locale dir in development context."""
        from src.core import i18n

        # Create a fake src/locale directory
        src_dir = tmp_path / "src"
        locale_dir = src_dir / "locale"
        locale_dir.mkdir(parents=True)

        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("os.path.exists", return_value=False),
            mock.patch(
                "os.path.dirname",
                side_effect=[
                    str(src_dir / "core"),  # First call: directory of i18n.py
                    str(src_dir),  # Second call: parent (src/)
                ],
            ),
            mock.patch("os.path.abspath", return_value=str(src_dir / "core" / "i18n.py")),
            mock.patch("os.path.isdir") as mock_isdir,
        ):
            os.environ.pop("APPDIR", None)

            def isdir_side_effect(path):
                return path == str(locale_dir)

            mock_isdir.side_effect = isdir_side_effect
            result = i18n._get_locale_dir()
            assert result == str(locale_dir)

    def test_system_locale_fallback(self):
        """Falls back to /usr/share/locale when available."""
        from src.core import i18n

        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("os.path.exists", return_value=False),
            mock.patch("os.path.isdir") as mock_isdir,
        ):
            os.environ.pop("APPDIR", None)

            def isdir_side_effect(path):
                return path == "/usr/share/locale"

            mock_isdir.side_effect = isdir_side_effect
            result = i18n._get_locale_dir()
            assert result == "/usr/share/locale"

    def test_returns_none_when_no_locale_dir(self):
        """Returns None when no locale directory is found."""
        from src.core import i18n

        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("os.path.exists", return_value=False),
            mock.patch("os.path.isdir", return_value=False),
        ):
            os.environ.pop("APPDIR", None)
            result = i18n._get_locale_dir()
            assert result is None
