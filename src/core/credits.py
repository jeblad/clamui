# ClamUI Credits
"""
Contributor credits for the About dialog.

The list lives in the packaged ``resources/AUTHORS`` file (one contributor per
line, optionally followed by a URL or ``<email>``, the form Adw.AboutDialog
accepts for developers), so it is available in every packaging format.
"""

from __future__ import annotations

import logging
from importlib.resources import files

logger = logging.getLogger(__name__)

AUTHORS_RESOURCE = "AUTHORS"


def load_developers() -> list[str]:
    """Return the contributor lines from the packaged AUTHORS file.

    Blank lines and lines starting with ``#`` are skipped. A missing or
    unreadable file yields an empty list, so the About dialog still opens.
    """
    package = f"{__name__.split('.', 1)[0]}.resources"
    try:
        text = (files(package) / AUTHORS_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        logger.warning("Contributor list %s/%s is unavailable", package, AUTHORS_RESOURCE)
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
