"""Property-based behavioral tests for src/core/threat_classifier.py."""

from __future__ import annotations

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from src.core.threat_classifier import (
    ThreatSeverity,
    categorize_threat,
    classify_threat_severity,
)
from tests.property.strategies import unknown_threat_name

pytestmark = pytest.mark.property


# These are independent, representative rules from the threat-name contract,
# with an explicit severity order rather than an oracle imported from production.
SEVERITY_CASES = (
    ("ransom", 4, ThreatSeverity.CRITICAL),
    ("rootkit", 4, ThreatSeverity.CRITICAL),
    ("bootkit", 4, ThreatSeverity.CRITICAL),
    ("cryptolocker", 4, ThreatSeverity.CRITICAL),
    ("wannacry", 4, ThreatSeverity.CRITICAL),
    ("trojan", 3, ThreatSeverity.HIGH),
    ("worm", 3, ThreatSeverity.HIGH),
    ("backdoor", 3, ThreatSeverity.HIGH),
    ("exploit", 3, ThreatSeverity.HIGH),
    ("downloader", 3, ThreatSeverity.HIGH),
    ("dropper", 3, ThreatSeverity.HIGH),
    ("keylogger", 3, ThreatSeverity.HIGH),
    ("adware", 2, ThreatSeverity.MEDIUM),
    ("pua", 2, ThreatSeverity.MEDIUM),
    ("pup", 2, ThreatSeverity.MEDIUM),
    ("spyware", 2, ThreatSeverity.MEDIUM),
    ("miner", 2, ThreatSeverity.MEDIUM),
    ("coinminer", 2, ThreatSeverity.MEDIUM),
    ("eicar", 1, ThreatSeverity.LOW),
    ("test-signature", 1, ThreatSeverity.LOW),
    ("test.file", 1, ThreatSeverity.LOW),
    ("heuristic", 1, ThreatSeverity.LOW),
    ("generic", 1, ThreatSeverity.LOW),
)

# These patterns have observable category behavior.  "ransomware" is omitted
# because it necessarily also matches "ransom" with the identical category,
# and "virus" is indistinguishable from the documented fallback.
HIGH_CATEGORY_CASES = (
    ("ransom", "Ransomware"),
    ("rootkit", "Rootkit"),
    ("bootkit", "Rootkit"),
    ("trojan", "Trojan"),
    ("worm", "Worm"),
    ("backdoor", "Backdoor"),
    ("exploit", "Exploit"),
    ("adware", "Adware"),
    ("spyware", "Spyware"),
    ("keylogger", "Spyware"),
    ("eicar", "Test"),
    ("test-signature", "Test"),
    ("test.file", "Test"),
    ("macro", "Macro"),
    ("phish", "Phishing"),
    ("heuristic", "Heuristic"),
)
LOW_CATEGORY_CASES = (("pua", "PUA"), ("pup", "PUA"))
CATEGORY_CASES = HIGH_CATEGORY_CASES + LOW_CATEGORY_CASES
DISTINCT_HIGH_CATEGORY_PAIRS = tuple(
    (first, second)
    for first in HIGH_CATEGORY_CASES
    for second in HIGH_CATEGORY_CASES
    if first[1] != second[1]
)
DISTINCT_LOW_CATEGORY_PAIRS = (
    (("pua", "PUA"), ("virus", "Virus")),
    (("pup", "PUA"), ("virus", "Virus")),
    (("virus", "Virus"), ("pua", "PUA")),
    (("virus", "Virus"), ("pup", "PUA")),
)


@st.composite
def _mixed_case_spelling(draw: st.DrawFn, pattern: str) -> str:
    alphabetic_positions = tuple(
        index for index, character in enumerate(pattern) if character.isalpha()
    )
    uppercase_positions = draw(
        st.sets(
            st.sampled_from(alphabetic_positions),
            min_size=1,
            max_size=len(alphabetic_positions) - 1,
        )
    )
    return "".join(
        character.upper() if index in uppercase_positions else character.lower()
        for index, character in enumerate(pattern)
    )


SEVERITY_CASES_WITH_MIXED_SPELLINGS = st.sampled_from(SEVERITY_CASES).flatmap(
    lambda case: st.tuples(st.just(case), _mixed_case_spelling(case[0]))
)
CATEGORY_CASES_WITH_MIXED_SPELLINGS = st.sampled_from(CATEGORY_CASES).flatmap(
    lambda case: st.tuples(st.just(case), _mixed_case_spelling(case[0]))
)


@given(st.sampled_from((None, "")))
def test_missing_name_has_documented_defaults(name: str | None) -> None:
    assert classify_threat_severity(name) == ThreatSeverity.MEDIUM
    assert categorize_threat(name) == "Unknown"


@given(
    st.sampled_from(SEVERITY_CASES),
    st.text(alphabet="0123456789", max_size=12),
    st.text(alphabet="0123456789", max_size=12),
)
def test_representative_patterns_have_expected_severity(
    case: tuple[str, int, ThreatSeverity], prefix: str, suffix: str
) -> None:
    pattern, _, expected = case
    # Digits plus delimiter cannot create a second textual classifier pattern.
    assert classify_threat_severity(f"{prefix}#{pattern}#{suffix}") == expected


@example((("ransom", 4, ThreatSeverity.CRITICAL), "ransom"))
@example((("ransom", 4, ThreatSeverity.CRITICAL), "RANSOM"))
@given(SEVERITY_CASES_WITH_MIXED_SPELLINGS)
def test_severity_is_case_insensitive_against_independent_answers(
    rendered: tuple[tuple[str, int, ThreatSeverity], str],
) -> None:
    case, name = rendered
    _, _, expected = case
    assert classify_threat_severity(name) == expected


@given(
    st.sampled_from(SEVERITY_CASES),
    st.sampled_from(SEVERITY_CASES),
    st.booleans(),
)
def test_higher_severity_wins_when_patterns_compete(
    first: tuple[str, int, ThreatSeverity],
    second: tuple[str, int, ThreatSeverity],
    reverse_order: bool,
) -> None:
    first_pattern, first_rank, first_expected = first
    second_pattern, second_rank, second_expected = second
    name = (
        f"{second_pattern}#{first_pattern}"
        if reverse_order
        else f"{first_pattern}#{second_pattern}"
    )
    expected = first_expected if first_rank >= second_rank else second_expected
    assert classify_threat_severity(name) == expected


@example((("ransom", "Ransomware"), "ransom"))
@example((("ransom", "Ransomware"), "RANSOM"))
@given(CATEGORY_CASES_WITH_MIXED_SPELLINGS)
def test_representative_categories_are_case_insensitive(
    rendered: tuple[tuple[str, str], str],
) -> None:
    case, name = rendered
    _, expected = case
    assert categorize_threat(name) == expected


@given(st.sampled_from(DISTINCT_HIGH_CATEGORY_PAIRS), st.booleans())
def test_earliest_high_priority_category_wins(
    pair: tuple[tuple[str, str], tuple[str, str]], reverse_order: bool
) -> None:
    first, second = pair
    if reverse_order:
        first, second = second, first
    first_pattern, expected = first
    second_pattern, _ = second
    assert categorize_threat(f"{first_pattern}#{second_pattern}") == expected


@given(
    st.sampled_from(LOW_CATEGORY_CASES),
    st.sampled_from(HIGH_CATEGORY_CASES),
    st.booleans(),
)
def test_high_priority_category_beats_low_priority_at_any_position(
    low_case: tuple[str, str],
    high_case: tuple[str, str],
    high_first: bool,
) -> None:
    low_pattern, _ = low_case
    high_pattern, expected = high_case
    name = f"{high_pattern}#{low_pattern}" if high_first else f"{low_pattern}#{high_pattern}"
    assert categorize_threat(name) == expected


@given(st.sampled_from(DISTINCT_LOW_CATEGORY_PAIRS))
def test_earliest_low_priority_category_wins(pair: tuple[tuple[str, str], tuple[str, str]]) -> None:
    first, second = pair
    first_pattern, expected = first
    second_pattern, _ = second
    assert categorize_threat(f"{first_pattern}#{second_pattern}") == expected


@given(unknown_threat_name())
def test_unrecognized_names_use_nonempty_fallbacks(name: str) -> None:
    assert classify_threat_severity(name) == ThreatSeverity.MEDIUM
    assert categorize_threat(name) == "Virus"
