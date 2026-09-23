"""Unit tests for SPF parsing and email security scoring (no network)."""
from modules.email_security import _analyze_spf, _calculate_email_score


def test_spf_strict_fail():
    spf = _analyze_spf(["v=spf1 include:_spf.google.com -all"])
    assert spf["found"] is True
    assert spf["policy"] == "fail"
    assert spf["all_qualifier"] == "-all"
    assert "_spf.google.com" in " ".join(spf["mechanisms"]) or spf["mechanisms"]


def test_spf_softfail():
    spf = _analyze_spf(["v=spf1 mx ~all"])
    assert spf["policy"] == "softfail"


def test_spf_pass_all_is_flagged():
    spf = _analyze_spf(["v=spf1 +all"])
    assert spf["policy"] == "pass_all"
    assert any("+all" in issue for issue in spf["issues"])


def test_spf_missing():
    spf = _analyze_spf(["some-other-txt-record", "google-site-verification=abc"])
    assert spf["found"] is False
    assert spf["policy"] is None


def test_spf_no_all_qualifier():
    spf = _analyze_spf(["v=spf1 include:example.com"])
    assert spf["found"] is True
    assert spf["policy"] == "no_all"


def test_email_score_full_stack():
    spf = {"found": True, "policy": "fail"}
    dmarc = {"found": True, "policy": "reject", "rua": "mailto:x@y.com"}
    dkim = {"found": True}
    bimi = {"found": True}
    mta = {"found": True}
    score = _calculate_email_score(spf, dmarc, dkim, bimi, mta)
    assert score == 100


def test_email_score_empty():
    empty = {"found": False}
    score = _calculate_email_score(empty, empty, empty, empty, empty)
    assert score == 0


def test_email_score_partial_is_bounded():
    spf = {"found": True, "policy": "softfail"}
    dmarc = {"found": True, "policy": "none"}
    dkim = {"found": False}
    score = _calculate_email_score(spf, dmarc, dkim, {"found": False}, {"found": False})
    assert 0 < score < 100
