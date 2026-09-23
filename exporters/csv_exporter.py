"""
NetTrace v2 - CSV Exporter
Exports key metrics as CSV. Supports a single domain (one row) or a batch
(one row per domain, shared header) for SIEM/Excel ingestion.
"""
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List

# Stable column order shared by single and batch exports.
CSV_FIELDNAMES = [
    "domain", "analysis_date", "risk_score", "risk_level", "registrar",
    "creation_date", "expiration_date", "age_days", "ip_count", "subdomain_count",
    "open_ports", "spf_status", "dmarc_status", "dkim_found", "https_enabled",
    "headers_score", "waf", "cdn", "is_behind_cdn", "country",
    "archive_first_seen", "axfr_vulnerable", "takeover_candidates", "dnssec_enabled",
]


def _build_row(results: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a single analysis result dict into one CSV row."""
    domain = results.get("domain", "")
    analysis_date = results.get("analysis_date", datetime.now(timezone.utc).isoformat())

    # Scoring
    scoring = results.get("scoring") or {}
    risk_score = scoring.get("score", "")
    risk_level = scoring.get("risk_level", "")

    # WHOIS
    whois = results.get("whois") or {}
    registrar = whois.get("registrar", "")
    creation_date = whois.get("creation_date", "")
    expiration_date = whois.get("expiration_date", "")
    age_days = whois.get("age_days", "")

    # DNS
    dns = results.get("dns") or {}
    ip_count = len(dns.get("a_records", []))
    dnssec_enabled = "Yes" if dns.get("dnssec_enabled") else "No"
    axfr_vulnerable = "No"
    for axfr in dns.get("axfr_results", []):
        if axfr.get("success"):
            axfr_vulnerable = "Yes"
            break

    # HTTP
    http = results.get("http") or {}
    https_enabled = "Yes" if http.get("https_reachable") else "No"
    headers_score = http.get("headers_score", "")
    waf = http.get("waf", "") or ""
    cdn_header = http.get("cdn", "") or ""

    # GeoIP
    geo = results.get("geo") or {}
    is_behind_cdn = "Yes" if geo.get("is_behind_cdn") else "No"
    detected_cdn = geo.get("detected_cdn", "") or cdn_header
    ip_info = geo.get("ip_info", [])
    country = ""
    if ip_info and ip_info[0].get("status") == "success":
        country = ip_info[0].get("country", "")

    # Subdomains
    subdomains = results.get("subdomains") or {}
    subdomain_count = subdomains.get("total_count", 0)
    takeover_candidates = len(subdomains.get("takeover_candidates", []))

    # Email
    email = results.get("email") or {}
    spf = email.get("spf", {})
    dmarc = email.get("dmarc", {})
    dkim = email.get("dkim", {})

    spf_status = spf.get("policy", "missing") if spf.get("found") else "missing"
    dmarc_status = dmarc.get("policy", "missing") if dmarc.get("found") else "missing"
    dkim_found = "Yes" if dkim.get("found") else "No"

    # Ports (may be None when the active scan was not run - guard explicitly)
    ports = results.get("ports") or {}
    open_port_nums = [str(p.get("port")) for p in ports.get("open_ports", [])]
    open_ports_str = ";".join(open_port_nums)

    # Archive
    archive = results.get("archive") or {}
    archive_first_seen = archive.get("first_seen", "")

    return {
        "domain": domain,
        "analysis_date": analysis_date,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "age_days": age_days,
        "ip_count": ip_count,
        "subdomain_count": subdomain_count,
        "open_ports": open_ports_str,
        "spf_status": spf_status,
        "dmarc_status": dmarc_status,
        "dkim_found": dkim_found,
        "https_enabled": https_enabled,
        "headers_score": headers_score,
        "waf": waf,
        "cdn": detected_cdn,
        "is_behind_cdn": is_behind_cdn,
        "country": country,
        "archive_first_seen": archive_first_seen,
        "axfr_vulnerable": axfr_vulnerable,
        "takeover_candidates": takeover_candidates,
        "dnssec_enabled": dnssec_enabled,
    }


def export_csv(results: Dict[str, Any], filename: str) -> bool:
    """
    Export key domain metrics as a single-row CSV file.

    Args:
        results: complete analysis results dict
        filename: output file path

    Returns:
        True on success, False on failure
    """
    try:
        row = _build_row(results)
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerow(row)
        return True
    except (OSError, TypeError, AttributeError):
        return False


def export_csv_batch(results_list: List[Dict[str, Any]], filename: str) -> bool:
    """
    Export several analysis results as a multi-row CSV (one row per domain),
    ideal for batch runs feeding a SIEM or spreadsheet.

    Args:
        results_list: list of complete analysis result dicts
        filename: output file path

    Returns:
        True on success, False on failure
    """
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            for results in results_list:
                if results:
                    writer.writerow(_build_row(results))
        return True
    except (OSError, TypeError, AttributeError):
        return False
