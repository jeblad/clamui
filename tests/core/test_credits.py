"""Tests for the About dialog contributor list."""

from __future__ import annotations

from pathlib import Path

from src.core import credits

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_root_authors_matches_packaged_copy():
    """The repository-root AUTHORS and the packaged resource stay identical."""
    root = (REPO_ROOT / "AUTHORS").read_text(encoding="utf-8")
    packaged = (REPO_ROOT / "src" / "resources" / "AUTHORS").read_text(encoding="utf-8")

    assert root == packaged


def test_load_developers_reads_packaged_authors():
    """The packaged AUTHORS loads as non-empty, stripped contributor lines."""
    developers = credits.load_developers()

    assert developers
    assert all(line == line.strip() and line for line in developers)


def test_load_developers_skips_blank_and_comment_lines(monkeypatch, tmp_path):
    """Blank lines and # comments are not shown as contributors."""
    (tmp_path / "AUTHORS").write_text(
        "# comment\n\nAda https://example.com\n  Bob <bob@example.com>  \n", encoding="utf-8"
    )
    monkeypatch.setattr(credits, "files", lambda _package: tmp_path)

    assert credits.load_developers() == ["Ada https://example.com", "Bob <bob@example.com>"]


def test_load_developers_returns_empty_list_when_resource_missing(monkeypatch, tmp_path):
    """A missing AUTHORS file yields an empty list so the dialog still opens."""
    monkeypatch.setattr(credits, "files", lambda _package: tmp_path)

    assert credits.load_developers() == []
