"""
NetTrace v2 - Plain Text Exporter
Exports analysis results as a formatted plain text report.
"""
from datetime import datetime
from typing import Dict, Any, List


def _section(title: str, width: int = 70) -> str:
    """Return a section header string."""
    line = "=" * width
    return f"\n{line}\n  {title}\n{line}\n"


def _subsection(title: str, width: int = 60) -> str:
    return f"\n  {'-' * width}\n  {title}\n  {'-' * width}\n"


def _fmt(value, default: str = "N/A") -> str:
    """Format a value, returning default if None/empty."""
    if value is None:
        return default
    v = str(value).strip()
    return v if v else default


def _list_to_str(lst: List, default: str = "None") -> str:
    """Format a list as comma-separated string."""
    if not lst:
        return default
    return ", ".join(str(x) for x in lst)


def export_txt(results: Dict[str, Any], filename: str) -> bool:
    """
    Export full analysis results to a formatted plain text report.

    Args:
        results: complete analysis results dict
        filename: output file path

    Returns:
        True on success, False on failure
    """
    try:
        lines = []
        domain = results.get("domain", "unknown")
        analysis_date = results.get("analysis_date", datetime.utcnow().isoformat())

        # Header
        lines.append("=" * 70)
        lines.append("  NETTRACE v2 - DOMAIN ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"  Domain:        {domain}")
        lines.append(f"  Analysis Date: {analysis_date}")

        # Risk Score
        scoring = results.get("scoring", {})
        if scoring:
            lines.append(f"  Risk Score:    {scoring.get('score', 'N/A')}/100")
            lines.append(f"  Risk Level:    {scoring.get('risk_label', 'N/A')}")
        lines.append("=" * 70)

        # WHOIS
        lines.append(_section("WHOIS INFORMATION"))
        whois = results.get("whois", {})
        if whois:
            lines.append(f"  Registrar:         {_fmt(whois.get('registrar'))}")
            lines.append(f"  Created:           {_fmt(whois.get('creation_date'))}")
            lines.append(f"  Expires:           {_fmt(whois.get('expiration_date'))}")
            lines.append(f"  Last Updated:      {_fmt(whois.get('updated_date'))}")
            lines.append(f"  Domain Age:        {_fmt(whois.get('age_days'))} days")
            lines.append(f"  Days Until Expiry: {_fmt(whois.get('days_until_expiry'))}")
            lines.append(f"  Registrant:        {_fmt(whois.get('registrant'))}")
            lines.append(f"  Organization:      {_fmt(whois.get('registrant_org'))}")
            lines.append(f"  Country:           {_fmt(whois.get('registrant_country'))}")
            lines.append(f"  Name Servers:      {_list_to_str(whois.get('name_servers', []))}")
            status_list = whois.get("status", [])
            if status_list:
                lines.append(f"  Status:")
                for s in status_list[:5]:
                    lines.append(f"    - {s}")

        # DNS
        lines.append(_section("DNS RECORDS"))
        dns = results.get("dns", {})
        if dns:
            record_types = [
                ("A Records", "a_records"),
                ("AAAA Records", "aaaa_records"),
                ("MX Records", "mx_records"),
                ("NS Records", "ns_records"),
                ("TXT Records", "txt_records"),
                ("CNAME Records", "cname_records"),
                ("SOA Records", "soa_records"),
            ]
            for label, key in record_types:
                records = dns.get(key, [])
                if records:
                    lines.append(f"  {label}:")
                    for r in records:
                        lines.append(f"    - {r}")
                else:
                    lines.append(f"  {label}: None")

            lines.append(f"\n  DNSSEC: {'Enabled' if dns.get('dnssec_enabled') else 'Disabled'}")

            axfr_list = dns.get("axfr_results", [])
            if axfr_list:
                lines.append("\n  Zone Transfer (AXFR) Tests:")
                for axfr in axfr_list:
                    ns = axfr.get("ns_name", axfr.get("ns", ""))
                    if axfr.get("success"):
                        lines.append(f"    [VULNERABLE] {ns} - AXFR SUCCESS ({len(axfr.get('records', []))} records)")
                    else:
                        lines.append(f"    [Blocked]    {ns} - {axfr.get('error', 'refused')}")

        # HTTP/TLS
        lines.append(_section("HTTP / TLS ANALYSIS"))
        http = results.get("http", {})
        if http:
            lines.append(f"  HTTP Status:           {_fmt(http.get('http_status'))}")
            lines.append(f"  HTTPS Status:          {_fmt(http.get('https_status'))}")
            lines.append(f"  HTTP -> HTTPS Redirect: {'Yes' if http.get('redirect_to_https') else 'No'}")
            lines.append(f"  Final URL:             {_fmt(http.get('final_url'))}")
            lines.append(f"  Server:                {_fmt(http.get('server'))}")
            lines.append(f"  X-Powered-By:          {_fmt(http.get('x_powered_by'))}")
            lines.append(f"  WAF Detected:          {_fmt(http.get('waf'))}")
            lines.append(f"  CDN (headers):         {_fmt(http.get('cdn'))}")
            lines.append(f"  Technologies:          {_list_to_str(http.get('technologies', []))}")
            lines.append(f"  Security Headers Score: {_fmt(http.get('headers_score'))}/100")

            sec_headers = http.get("security_headers", {})
            missing = http.get("missing_headers", [])
            lines.append("\n  Security Headers:")
            for header in [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
                "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
            ]:
                if header in sec_headers:
                    val = sec_headers[header]
                    short = val[:80] + "..." if len(val) > 80 else val
                    lines.append(f"    [PRESENT] {header}: {short}")
                else:
                    lines.append(f"    [MISSING] {header}")

            tls = http.get("tls_info", {})
            if tls and not tls.get("error"):
                lines.append("\n  TLS Certificate:")
                lines.append(f"    Version:          {_fmt(tls.get('tls_version'))}")
                lines.append(f"    Subject:          {_fmt(tls.get('subject'))}")
                lines.append(f"    Issuer:           {_fmt(tls.get('issuer'))}")
                lines.append(f"    Valid Until:      {_fmt(tls.get('not_after'))}")
                lines.append(f"    Days Until Expiry: {_fmt(tls.get('days_until_expiry'))}")
                san = tls.get("san", [])
                if san:
                    lines.append(f"    SAN:              {', '.join(san[:5])}")

        # GeoIP
        lines.append(_section("GEOIP ANALYSIS"))
        geo = results.get("geo", {})
        if geo:
            lines.append(f"  CDN Detected: {'Yes - ' + str(geo.get('detected_cdn')) if geo.get('is_behind_cdn') else 'No'}")
            lines.append(f"  Countries:    {_list_to_str(geo.get('unique_countries', []))}")
            lines.append(f"  ASNs:         {_list_to_str(geo.get('unique_asns', []))}")
            ip_info = geo.get("ip_info", [])
            if ip_info:
                lines.append("\n  IP Details:")
                for info in ip_info:
                    if info.get("status") == "success":
                        cdn_flag = f" [CDN: {info.get('cdn')}]" if info.get("cdn") else ""
                        lines.append(
                            f"    {info.get('ip')}: {info.get('country')}, {info.get('city')} | "
                            f"{info.get('as')} | {info.get('org')}{cdn_flag}"
                        )

        # Subdomains
        lines.append(_section("SUBDOMAIN ENUMERATION"))
        subdomains = results.get("subdomains", {})
        if subdomains:
            lines.append(f"  Total Found: {subdomains.get('total_count', 0)}")
            sources = subdomains.get("sources", {})
            for src, count in sources.items():
                lines.append(f"  Source [{src}]: {count}")

            sub_list = subdomains.get("subdomains", [])
            if sub_list:
                lines.append("\n  Subdomains:")
                for sub in sub_list[:50]:
                    lines.append(f"    - {sub}")
                if len(sub_list) > 50:
                    lines.append(f"    ... and {len(sub_list) - 50} more")

            takeover = subdomains.get("takeover_candidates", [])
            if takeover:
                lines.append("\n  [!] POTENTIAL TAKEOVER CANDIDATES:")
                for t in takeover:
                    confirmed = "CONFIRMED" if t.get("confirmed") else "Possible"
                    lines.append(f"    [{confirmed}] {t.get('subdomain')} -> CNAME: {t.get('cname')} ({t.get('service')})")

        # Email Security
        lines.append(_section("EMAIL SECURITY"))
        email = results.get("email", {})
        if email:
            lines.append(f"  Email Security Score: {email.get('email_score', 0)}/100")

            spf = email.get("spf", {})
            lines.append(f"\n  SPF:")
            if spf.get("found"):
                lines.append(f"    Status:  Configured")
                lines.append(f"    Policy:  {spf.get('policy', 'N/A')}")
                lines.append(f"    Record:  {_fmt(spf.get('record'))[:100]}")
            else:
                lines.append(f"    Status:  MISSING")

            dmarc = email.get("dmarc", {})
            lines.append(f"\n  DMARC:")
            if dmarc.get("found"):
                lines.append(f"    Status:  Configured")
                lines.append(f"    Policy:  {dmarc.get('policy', 'N/A')}")
                lines.append(f"    pct:     {dmarc.get('pct', 100)}%")
                lines.append(f"    rua:     {_fmt(dmarc.get('rua'))}")
            else:
                lines.append(f"    Status:  MISSING")

            dkim = email.get("dkim", {})
            lines.append(f"\n  DKIM:")
            if dkim.get("found"):
                selectors = dkim.get("found_selectors", [])
                lines.append(f"    Status:    Found")
                lines.append(f"    Selectors: {', '.join(selectors)}")
            else:
                lines.append(f"    Status:  Not found (common selectors checked)")

            bimi = email.get("bimi", {})
            lines.append(f"\n  BIMI:    {'Configured' if bimi.get('found') else 'Not configured'}")

            mta = email.get("mta_sts", {})
            lines.append(f"  MTA-STS: {'Configured' if mta.get('found') else 'Not configured'}")

            issues = email.get("issues", [])
            if issues:
                lines.append("\n  Issues:")
                for issue in issues:
                    lines.append(f"    - {issue}")

        # Archive
        lines.append(_section("WAYBACK MACHINE ARCHIVE"))
        archive = results.get("archive", {})
        if archive:
            lines.append(f"  Available:       {'Yes' if archive.get('available') else 'No'}")
            lines.append(f"  First Seen:      {_fmt(archive.get('first_seen'))}")
            lines.append(f"  Last Seen:       {_fmt(archive.get('last_seen'))}")
            lines.append(f"  Total Snapshots: ~{_fmt(archive.get('snapshot_count'))}")
            lines.append(f"  Latest URL:      {_fmt(archive.get('wayback_url'))}")
            interesting = archive.get("interesting_urls", [])
            if interesting:
                lines.append(f"\n  Interesting Archived URLs ({len(interesting)}):")
                for url in interesting[:20]:
                    lines.append(f"    - {url}")

        # Port Scan
        ports = results.get("ports", {})
        if ports:
            lines.append(_section("PORT SCAN RESULTS"))
            open_ports = ports.get("open_ports", [])
            if open_ports:
                lines.append(f"  Open Ports: {len(open_ports)}")
                for p in open_ports:
                    banner = p.get("banner") or "N/A"
                    lines.append(f"    Port {p.get('port')}/{p.get('service')}: {banner}")
            else:
                lines.append("  No open ports found on scanned ports.")

        # Risk Assessment
        if scoring:
            lines.append(_section("RISK ASSESSMENT"))
            lines.append(f"  Score:      {scoring.get('score', 0)}/100")
            lines.append(f"  Risk Level: {scoring.get('risk_label', 'N/A')}")

            breakdown = scoring.get("breakdown", {})
            if breakdown:
                lines.append("\n  Score Breakdown:")
                for key, data in breakdown.items():
                    label = key.replace("_", " ").title()
                    lines.append(f"    {label}: {data.get('score', 0)}/{data.get('max', 0)} - {data.get('detail', '')}")

            recs = scoring.get("recommendations", [])
            if recs:
                lines.append("\n  Recommendations:")
                for rec in recs:
                    lines.append(f"    - {rec}")

        # Dorks
        dorks_data = results.get("dorks", {})
        if dorks_data:
            lines.append(_section("GOOGLE DORKS"))
            for category, dork_list in dorks_data.get("dorks", {}).items():
                lines.append(f"\n  {category}:")
                for dork in dork_list:
                    lines.append(f"    {dork}")

        lines.append("\n" + "=" * 70)
        lines.append("  Report generated by NetTrace v2")
        lines.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("=" * 70 + "\n")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return True

    except (OSError, TypeError, AttributeError):
        return False
