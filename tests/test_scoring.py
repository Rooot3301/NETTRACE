"""Unit tests for the unified trust/maturity scoring (no network)."""
from modules.scoring import calculate_risk_score, RISK_LOW, RISK_HIGH


def _established_domain():
    whois = {
        "registrar": "Example Registrar",
        "creation_date": "2005-01-01T00:00:00+00:00",
        "expiration_date": "2030-01-01T00:00:00+00:00",
        "age_days": 365 * 19,
        "days_until_expiry": 365 * 4,
        "registrant_org": "Example Inc",
    }
    dns = {"a_records": ["1.2.3.4"], "mx_records": ["mx.example.com"],
           "ns_records": ["ns1.example.com"], "axfr_results": []}
    http = {"https_reachable": True, "redirect_to_https": True, "headers_score": 90,
            "security_headers": {"Strict-Transport-Security": "x", "Content-Security-Policy": "y",
                                 "X-Frame-Options": "DENY"}, "tls_info": {"days_until_expiry": 200}}
    email = {"email_score": 100, "spf": {"found": True, "policy": "fail"},
             "dmarc": {"found": True, "policy": "reject"}, "dkim": {"found": True}}
    subs = {"total_count": 25, "takeover_candidates": []}
    archive = {"available": True, "first_seen": "2006-01-01"}
    return whois, dns, http, email, subs, archive


def test_established_domain_scores_high():
    whois, dns, http, email, subs, archive = _established_domain()
    result = calculate_risk_score(whois, dns, http, {}, subs, email, archive, None)
    assert result["score"] >= 80
    assert result["risk_level"] == RISK_LOW
    assert 0 <= result["score"] <= 100


def test_empty_domain_scores_low():
    result = calculate_risk_score({}, {}, {}, {}, {}, {}, {}, None)
    assert result["score"] < 40
    assert result["risk_level"] == RISK_HIGH


def test_score_is_bounded_and_has_breakdown():
    whois, dns, http, email, subs, archive = _established_domain()
    result = calculate_risk_score(whois, dns, http, {}, subs, email, archive, None)
    assert set(result["breakdown"].keys()) >= {
        "domain_age", "dns_completeness", "email_security",
        "https_headers", "subdomain_presence", "whois_completeness", "archive_presence",
    }
    assert isinstance(result["recommendations"], list)


def test_spf_pass_all_triggers_critical_recommendation():
    email = {"email_score": 5, "spf": {"found": True, "policy": "pass_all"},
             "dmarc": {"found": False}, "dkim": {"found": False}}
    result = calculate_risk_score({}, {}, {}, {}, {}, email, {}, None)
    assert any("CRITICAL" in r and "+all" in r for r in result["recommendations"])


def test_confirmed_takeover_triggers_critical():
    subs = {"total_count": 3, "takeover_candidates": [
        {"subdomain": "old.example.com", "cname": "x.herokuapp.com", "confirmed": True}]}
    result = calculate_risk_score({}, {}, {}, {}, subs, {}, {}, None)
    assert any("CRITICAL" in r and "takeover" in r.lower() for r in result["recommendations"])
