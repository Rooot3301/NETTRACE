"""Unit tests for the CSV exporter, including the ports=None regression."""
import csv

from exporters.csv_exporter import export_csv, export_csv_batch, _build_row, CSV_FIELDNAMES


def _sample(domain="example.com", ports=None):
    return {
        "domain": domain,
        "analysis_date": "2026-01-01T00:00:00+00:00",
        "scoring": {"score": 88, "risk_level": "LOW_RISK"},
        "whois": {"registrar": "R", "creation_date": "2005-01-01", "age_days": 7000},
        "dns": {"a_records": ["1.2.3.4"], "dnssec_enabled": True, "axfr_results": []},
        "http": {"https_reachable": True, "headers_score": 80, "waf": "Cloudflare"},
        "geo": {"is_behind_cdn": True, "detected_cdn": "Cloudflare",
                "ip_info": [{"status": "success", "country": "France"}]},
        "subdomains": {"total_count": 12, "takeover_candidates": []},
        "email": {"spf": {"found": True, "policy": "fail"},
                  "dmarc": {"found": True, "policy": "reject"},
                  "dkim": {"found": True}},
        "archive": {"first_seen": "2006-01-01"},
        "ports": ports,  # None in the default (passive) case
    }


def test_build_row_with_ports_none_does_not_raise():
    # Regression: passive runs leave ports=None; this must not crash.
    row = _build_row(_sample(ports=None))
    assert row["open_ports"] == ""
    assert row["domain"] == "example.com"


def test_export_csv_passive_succeeds(tmp_path):
    out = tmp_path / "report.csv"
    ok = export_csv(_sample(ports=None), str(out))
    assert ok is True
    with open(out, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["risk_score"] == "88"
    assert rows[0]["open_ports"] == ""


def test_export_csv_with_open_ports(tmp_path):
    out = tmp_path / "report.csv"
    data = _sample(ports={"open_ports": [{"port": 80}, {"port": 443}]})
    assert export_csv(data, str(out)) is True
    with open(out, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["open_ports"] == "80;443"


def test_export_csv_batch_multiple_rows(tmp_path):
    out = tmp_path / "batch.csv"
    data = [_sample("a.com"), _sample("b.com"), _sample("c.com")]
    assert export_csv_batch(data, str(out)) is True
    with open(out, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_FIELDNAMES
        rows = list(reader)
    assert [r["domain"] for r in rows] == ["a.com", "b.com", "c.com"]
