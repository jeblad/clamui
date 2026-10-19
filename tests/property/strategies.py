"""
Shared Hypothesis strategies for ClamUI property tests.

These composite strategies generate adversarial sanitizer inputs and
construct unknown classifier names.
"""

from __future__ import annotations

import string

from hypothesis import strategies as st

ANSI_FRAGMENTS = [
    "\x1b[31m",
    "\x1b[0m",
    "\x1b[1;32m",
    "\x1b[?25h",
    "\x1b[H",
    "\x1bP",
]

BIDI_CHARS = [
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
]

C1_CONTROL_CHARS = [chr(codepoint) for codepoint in range(0x80, 0xA0)]
LINE_SEPARATOR_CHARS = ["\u0085", "\u2028", "\u2029"]
CONTROL_CHARS = [chr(c) for c in range(0x00, 0x20) if c != 0x09] + ["\x7f"]


@st.composite
def adversarial_text(draw: st.DrawFn) -> str:
    """
    Build a string with random mixes of ANSI escapes, controls, separators,
    bidirectional controls, explicit lone surrogates, and ordinary text.
    """
    pieces = draw(
        st.lists(
            st.one_of(
                st.text(max_size=20),
                st.sampled_from(ANSI_FRAGMENTS),
                st.sampled_from(BIDI_CHARS),
                st.sampled_from(CONTROL_CHARS),
                st.sampled_from(C1_CONTROL_CHARS),
                st.sampled_from(LINE_SEPARATOR_CHARS),
                st.text(
                    alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF),
                    min_size=1,
                    max_size=5,
                ),
            ),
            max_size=12,
        )
    )
    return "".join(pieces)


@st.composite
def surrogate_text(draw: st.DrawFn) -> str:
    """
    Text that may contain lone surrogate code points (U+D800-U+DFFF).
    These typically arise from surrogateescape-decoded non-UTF-8 filenames.
    """
    parts = draw(
        st.lists(
            st.one_of(
                st.text(max_size=10),
                st.text(
                    alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF),
                    max_size=3,
                ),
            ),
            max_size=6,
        )
    )
    return "".join(parts)


# The alphabet deliberately excludes vowels: every classifier and category
# keyword contains at least one, so a separator-delimited generated name cannot
# accidentally contain one of those keywords.
UNKNOWN_TOKEN_ALPHABET = (
    string.ascii_lowercase.translate(str.maketrans("", "", "aeiouy")) + string.digits
)


@st.composite
def unknown_threat_name(draw: st.DrawFn) -> str:
    """
    Construct diverse, ClamAV-shaped unknown names without rejection or a
    fixed fallback. Consonant-and-digit tokens are joined by one delimiter.
    """
    tokens = draw(
        st.lists(
            st.text(alphabet=UNKNOWN_TOKEN_ALPHABET, min_size=1, max_size=10),
            min_size=2,
            max_size=4,
        )
    )
    separator = draw(st.sampled_from((".", "-", "_")))
    return separator.join(tokens)
