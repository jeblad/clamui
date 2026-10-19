"""Property-based behavior tests for :mod:`src.core.sanitize`."""

from __future__ import annotations

import string
from collections.abc import Callable

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from src.core.sanitize import (
    REDACTED_HASH,
    REDACTED_PATH,
    REDACTED_URL,
    redact_sensitive_log_data,
    sanitize_log_line,
    sanitize_log_text,
    sanitize_path_for_logging,
    sanitize_surrogate_path,
)
from tests.property.strategies import adversarial_text, surrogate_text

pytestmark = pytest.mark.property

LogSanitizer = Callable[[str | None], str]
LOG_SANITIZERS: tuple[LogSanitizer, ...] = (sanitize_log_line, sanitize_log_text)
REDACTORS: tuple[LogSanitizer, ...] = (
    redact_sensitive_log_data,
    sanitize_path_for_logging,
)

BIDI_CHARACTERS = (
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
)
C1_CONTROL_CHARACTERS = tuple(chr(code) for code in range(0x80, 0xA0))
UNICODE_LINE_SEPARATORS = ("\u0085", "\u2028", "\u2029")
LINE_BREAK_CHARACTERS = (
    "\n",
    "\r",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    *UNICODE_LINE_SEPARATORS,
)
HEX_DIGITS = string.hexdigits
SAFE_LINE_ALPHABET = string.ascii_letters + string.digits + " .,_-\tΩ"
SAFE_MULTILINE_ALPHABET = SAFE_LINE_ALPHABET + "\n\r"
VISIBLE_FRAGMENT = st.text(
    alphabet=string.ascii_letters + string.digits + " .,_-Ω",
    max_size=30,
)

SAFE_SEGMENT = st.text(
    alphabet=string.ascii_letters + string.digits + " .,_-Ω",
    min_size=1,
    max_size=30,
)
SURROGATE_RUN = st.text(
    alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF),
    min_size=1,
    max_size=4,
)


@st.composite
def redaction_path(draw: st.DrawFn) -> str:
    """Generate a path in one supported form with no ambiguous terminator."""
    segment = draw(
        st.text(
            alphabet=string.ascii_letters + string.digits + "_-",
            min_size=1,
            max_size=20,
        )
    )
    filename = draw(
        st.text(
            alphabet=string.ascii_letters + string.digits + "_-",
            min_size=1,
            max_size=20,
        )
    )
    path_kind = draw(st.sampled_from(("native", "home", "windows", "file_uri")))

    if path_kind == "native":
        return f"/home/{segment}/{filename}.txt"
    if path_kind == "home":
        return f"~/{segment}/{filename}.txt"
    if path_kind == "windows":
        return f"C:\\Users\\{segment}\\{filename}.txt"
    return f"file:///var/{segment}/{filename}.txt"


@st.composite
def bounded_hex_value(draw: st.DrawFn) -> tuple[int, str]:
    """Generate hash-shaped values immediately around the privacy boundary."""
    length = draw(st.sampled_from((31, 32, 128, 129)))
    return length, draw(st.text(alphabet=HEX_DIGITS, min_size=length, max_size=length))


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(path=redaction_path(), prefix=VISIBLE_FRAGMENT, suffix=VISIBLE_FRAGMENT)
@example(path="/home/alice/private.txt", prefix="before ", suffix=" after")
@example(path="~/Documents/private.txt", prefix="before ", suffix=" after")
@example(path="C:\\Users\\alice\\private.txt", prefix="before ", suffix=" after")
@example(path="file:///var/tmp/private.txt", prefix="before ", suffix=" after")
def test_redactors_replace_each_delimited_path_without_leaking_it(
    sanitizer: LogSanitizer,
    path: str,
    prefix: str,
    suffix: str,
) -> None:
    """Each supported path form is wholly replaced inside stable delimiters."""
    text = f"{prefix}({path}){suffix}"

    result = sanitizer(text)

    assert result == f"{prefix}({REDACTED_PATH}){suffix}"
    assert path not in result
    assert result.startswith(f"{prefix}(")
    assert result.endswith(f"){suffix}")


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(
    paths=st.lists(redaction_path(), min_size=2, max_size=4, unique=True),
    prefix=VISIBLE_FRAGMENT,
    suffix=VISIBLE_FRAGMENT,
)
def test_redactors_replace_every_distinct_delimited_path(
    sanitizer: LogSanitizer,
    paths: list[str],
    prefix: str,
    suffix: str,
) -> None:
    separator = ") :: ("
    text = f"{prefix}(" + separator.join(paths) + f"){suffix}"

    result = sanitizer(text)

    expected = f"{prefix}(" + separator.join([REDACTED_PATH] * len(paths)) + f"){suffix}"
    assert result == expected
    assert all(path not in result for path in paths)
    assert result.count(separator) == len(paths) - 1


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(case=bounded_hex_value())
@example(case=(31, "a" * 31))
@example(case=(32, "A" * 32))
@example(case=(128, "b" * 128))
@example(case=(129, "C" * 129))
def test_redactors_respect_hash_length_boundaries(
    sanitizer: LogSanitizer,
    case: tuple[int, str],
) -> None:
    """Only complete, word-bounded 32--128 character hex values are private."""
    length, value = case
    text = f"before[{value}]after"

    result = sanitizer(text)

    if 32 <= length <= 128:
        assert result == f"before[{REDACTED_HASH}]after"
        assert value not in result
    else:
        assert result == text
        assert REDACTED_HASH not in result


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(value=st.text(alphabet=HEX_DIGITS, min_size=32, max_size=128))
def test_redactors_do_not_redact_hashes_embedded_in_words(
    sanitizer: LogSanitizer,
    value: str,
) -> None:
    for word_character in ("g", "_"):
        text = f"before{word_character}{value}{word_character}after"

        result = sanitizer(text)

        assert result == text
        assert REDACTED_HASH not in result


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(
    scheme=st.sampled_from(("http", "https")),
    host=st.sampled_from(("virustotal.com", "www.virustotal.com")),
    value=st.text(alphabet=HEX_DIGITS, min_size=32, max_size=128),
)
def test_redactors_replace_virustotal_urls_as_a_unit(
    sanitizer: LogSanitizer,
    scheme: str,
    host: str,
    value: str,
) -> None:
    url = f"{scheme}://{host}/gui/file/{value}"
    text = f"report {url} complete"

    result = sanitizer(text)

    assert result == f"report {REDACTED_URL} complete"
    assert url not in result
    assert value not in result


@pytest.mark.parametrize("sanitizer", REDACTORS)
@given(
    path=redaction_path(),
    value=st.text(alphabet=HEX_DIGITS, min_size=32, max_size=128),
)
def test_redactors_are_idempotent_after_redacting_distinct_values(
    sanitizer: LogSanitizer,
    path: str,
    value: str,
) -> None:
    url = f"https://www.virustotal.com/gui/file/{value}"
    text = f"target ({path}) hash [{value}] report {url} completed"

    once = sanitizer(text)

    assert once == (
        f"target ({REDACTED_PATH}) hash [{REDACTED_HASH}] report {REDACTED_URL} completed"
    )
    assert path not in once
    assert value not in once
    assert url not in once
    assert sanitizer(once) == once


@pytest.mark.parametrize("sanitizer", LOG_SANITIZERS)
@given(prefix=VISIBLE_FRAGMENT, payload=VISIBLE_FRAGMENT, suffix=VISIBLE_FRAGMENT)
def test_log_sanitizers_remove_explicit_ansi_wrappers_but_keep_payload(
    sanitizer: LogSanitizer,
    prefix: str,
    payload: str,
    suffix: str,
) -> None:
    text = f"{prefix}\x1b[31m{payload}\x1b[0m{suffix}"

    assert sanitizer(text) == f"{prefix}{payload}{suffix}"


@pytest.mark.parametrize("sanitizer", LOG_SANITIZERS)
@given(prefix=VISIBLE_FRAGMENT, suffix=VISIBLE_FRAGMENT)
def test_log_sanitizers_remove_every_bidirectional_format_character(
    sanitizer: LogSanitizer,
    prefix: str,
    suffix: str,
) -> None:
    for character in BIDI_CHARACTERS:
        result = sanitizer(f"{prefix}{character}{suffix}")
        assert result == f"{prefix}{suffix}"
        assert character not in result


@pytest.mark.parametrize("sanitizer", LOG_SANITIZERS)
@given(prefix=VISIBLE_FRAGMENT, suffix=VISIBLE_FRAGMENT)
def test_log_sanitizers_handle_all_c1_and_unicode_line_separators(
    sanitizer: LogSanitizer,
    prefix: str,
    suffix: str,
) -> None:
    for character in (*C1_CONTROL_CHARACTERS, "\u2028", "\u2029"):
        expected_middle = " " if character in UNICODE_LINE_SEPARATORS else ""
        result = sanitizer(f"{prefix}{character}{suffix}")
        assert result == f"{prefix}{expected_middle}{suffix}"


@given(adversarial_text())
def test_sanitize_log_line_has_no_log_line_break_or_forbidden_controls(text: str) -> None:
    result = sanitize_log_line(text)

    assert all(character not in result for character in LINE_BREAK_CHARACTERS)
    for character in result:
        codepoint = ord(character)
        assert codepoint == 0x09 or codepoint >= 0x20
        assert not 0x80 <= codepoint <= 0x9F
        assert codepoint != 0x7F


@given(adversarial_text())
def test_sanitize_log_text_keeps_only_explicitly_allowed_line_breaks(text: str) -> None:
    result = sanitize_log_text(text)

    assert all(character not in result for character in UNICODE_LINE_SEPARATORS)
    for character in result:
        codepoint = ord(character)
        assert codepoint in (0x09, 0x0A, 0x0D) or codepoint >= 0x20
        assert not 0x80 <= codepoint <= 0x9F
        assert codepoint != 0x7F


@given(prefix=VISIBLE_FRAGMENT, suffix=VISIBLE_FRAGMENT)
def test_log_sanitizers_preserve_legitimate_whitespace_with_their_line_contracts(
    prefix: str,
    suffix: str,
) -> None:
    shared_whitespace = " \t  \t "
    assert (
        sanitize_log_line(f"{prefix}{shared_whitespace}{suffix}")
        == f"{prefix}{shared_whitespace}{suffix}"
    )
    assert (
        sanitize_log_text(f"{prefix}{shared_whitespace}{suffix}")
        == f"{prefix}{shared_whitespace}{suffix}"
    )

    line_breaks = "\r\n"
    assert sanitize_log_line(f"{prefix}{line_breaks}{suffix}") == f"{prefix}  {suffix}"
    assert sanitize_log_text(f"{prefix}{line_breaks}{suffix}") == f"{prefix}{line_breaks}{suffix}"


@given(st.text(alphabet=SAFE_LINE_ALPHABET))
def test_log_sanitizers_are_identity_for_safe_single_line_input(text: str) -> None:
    assert sanitize_log_line(text) == text
    assert sanitize_log_text(text) == text


@given(st.text(alphabet=SAFE_MULTILINE_ALPHABET))
def test_sanitize_log_text_is_identity_for_safe_multiline_input(text: str) -> None:
    assert sanitize_log_text(text) == text


@given(adversarial_text())
def test_log_sanitizers_are_idempotent(text: str) -> None:
    for sanitizer in LOG_SANITIZERS:
        once = sanitizer(text)
        assert sanitizer(once) == once


@given(adversarial_text())
def test_log_sanitizers_emit_utf8_from_raw_adversarial_text(text: str) -> None:
    for sanitizer in LOG_SANITIZERS:
        result = sanitizer(text)
        result.encode("utf-8")
        assert all(not 0xD800 <= ord(character) <= 0xDFFF for character in result)


@given(surrogate_text())
def test_log_sanitizers_emit_utf8_without_surrogates_from_raw_surrogate_text(
    text: str,
) -> None:
    for sanitizer in LOG_SANITIZERS:
        result = sanitizer(text)
        result.encode("utf-8")
        assert all(not 0xD800 <= ord(character) <= 0xDFFF for character in result)


@given(
    prefix=SAFE_SEGMENT,
    first_run=SURROGATE_RUN,
    middle=SAFE_SEGMENT,
    second_run=SURROGATE_RUN,
    suffix=SAFE_SEGMENT,
)
@example(
    prefix="before",
    first_run="\ud800",
    middle="middle",
    second_run="\udfff",
    suffix="after",
)
def test_log_sanitizers_remove_surrogate_runs_without_losing_safe_segments(
    prefix: str,
    first_run: str,
    middle: str,
    second_run: str,
    suffix: str,
) -> None:
    text = f"{prefix}{first_run}{middle}{second_run}{suffix}"
    expected = f"{prefix}{middle}{suffix}"

    for sanitizer in LOG_SANITIZERS:
        result = sanitizer(text)
        result.encode("utf-8")
        assert result == expected


@given(st.text())
def test_sanitize_surrogate_path_preserves_utf8_text(text: str) -> None:
    """Already encodable Unicode is preserved, including whitespace and controls."""
    assert sanitize_surrogate_path(text) == text


@given(
    prefix=SAFE_SEGMENT,
    first_run=SURROGATE_RUN,
    middle=SAFE_SEGMENT,
    second_run=SURROGATE_RUN,
    suffix=SAFE_SEGMENT,
)
@example(
    prefix="before",
    first_run="\ud800",
    middle="middle",
    second_run="\udfff",
    suffix="after",
)
def test_sanitize_surrogate_path_replaces_runs_and_preserves_valid_segments(
    prefix: str,
    first_run: str,
    middle: str,
    second_run: str,
    suffix: str,
) -> None:
    text = f"{prefix}{first_run}{middle}{second_run}{suffix}"
    expected = prefix + "\ufffd" * len(first_run) + middle + "\ufffd" * len(second_run) + suffix

    result = sanitize_surrogate_path(text)

    assert result == expected
    result.encode("utf-8")


@pytest.mark.parametrize("sanitizer", [*LOG_SANITIZERS, *REDACTORS])
def test_text_sanitizers_return_empty_text_for_none(sanitizer: LogSanitizer) -> None:
    assert sanitizer(None) == ""
