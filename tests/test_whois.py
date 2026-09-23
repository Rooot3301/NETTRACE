"""Unit tests for robust WHOIS date parsing (no network)."""
from datetime import datetime, timezone

from modules.whois_analysis import _parse_date, _extract_str


def test_parse_none():
    assert _parse_date(None) is None


def test_parse_naive_datetime_gets_utc():
    dt = _parse_date(datetime(2020, 1, 1, 12, 0, 0))
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_aware_datetime_preserved():
    aware = datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert _parse_date(aware) == aware


def test_parse_list_takes_first():
    dt = _parse_date([datetime(2019, 5, 4), datetime(2021, 1, 1)])
    assert dt is not None
    assert dt.year == 2019


def test_parse_string():
    dt = _parse_date("2015-06-15T00:00:00")
    assert dt is not None
    assert dt.year == 2015 and dt.month == 6


def test_parse_invalid_string():
    assert _parse_date("not-a-date") is None


def test_extract_str_from_list():
    assert _extract_str(["a", "b"]) == "a"


def test_extract_str_from_none():
    assert _extract_str(None) == ""
