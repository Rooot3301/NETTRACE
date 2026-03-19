"""
NetTrace v2 - Risk Scoring Module
Calculates a unified risk/trust score for a domain based on all analysis results.
Higher score = more established/safer. Lower score = riskier/more suspicious.
"""
from typing import Dict, Any, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Risk levels
RISK_LOW = "LOW_RISK"
RISK_MEDIUM = "MEDIUM_RISK"
RISK_ELEVATED = "ELEVATED_RISK"
RISK_HIGH = "HIGH_RISK"

RISK_COLORS = {
    RISK_LOW: "green",
    RISK_MEDIUM: "yellow",
    RISK_ELEVATED: "dark_orange",
    RISK_HIGH: "red",
}

RISK_LABELS = {
    RISK_LOW: "Low Risk",
    RISK_MEDIUM: "Medium Risk",
    RISK_ELEVATED: "Elevated Risk",
    RISK_HIGH: "High Risk",
}


def _score_domain_age(whois_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on domain age.
    Max 25 points.
    >=10 years = 25, >=5 years = 20, >=3 years = 18, >=1 year = 10, <1 year = 0
    """
    age_days = whois_data.get("age_days") if whois_data else None
    if age_days is None:
        return {"score": 0, "max": 25, "detail": "Domain age unknown (WHOIS unavailable)"}

    if age_days >= 365 * 10:
        score = 25
        detail = f"Domain age: {age_days // 365} years (very established)"
    elif age_days >= 365 * 5:
        score = 20
        detail = f"Domain age: {age_days // 365} years (well established)"
    elif age_days >= 365 * 3:
        score = 18
        detail = f"Domain age: {age_days // 365} years (established)"
    elif age_days >= 365:
        score = 10
        detail = f"Domain age: {age_days // 365} year(s) (relatively new)"
    elif age_days >= 180:
        score = 5
        detail = f"Domain age: {age_days} days (new domain)"
    else:
        score = 0
        detail = f"Domain age: {age_days} days (very new - suspicious)"

    return {"score": score, "max": 25, "detail": detail}


def _score_dns_completeness(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on DNS record completeness.
    Max 15 points. A record = 5, MX = 5, NS = 5.
    """
    if not dns_data:
        return {"score": 0, "max": 15, "detail": "DNS data unavailable"}

    score = 0
    missing = []

    if dns_data.get("a_records"):
        score += 5
    else:
        missing.append("A")

    if dns_data.get("mx_records"):
        score += 5
    else:
        missing.append("MX")

    if dns_data.get("ns_records"):
        score += 5
    else:
        missing.append("NS")

    if missing:
        detail = f"Missing records: {', '.join(missing)}"
    else:
        detail = "A, MX, NS records all present"

    return {"score": score, "max": 15, "detail": detail}


def _score_email_security(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on email security configuration.
    Max 20 points. Uses email_score (0-100) scaled to 20.
    """
    if not email_data:
        return {"score": 0, "max": 20, "detail": "Email security data unavailable"}

    email_score = email_data.get("email_score", 0)
    scaled = int((email_score / 100) * 20)

    spf = email_data.get("spf", {})
    dmarc = email_data.get("dmarc", {})
    dkim = email_data.get("dkim", {})

    parts = []
    if spf.get("found"):
        parts.append(f"SPF({spf.get('policy', 'n/a')})")
    if dmarc.get("found"):
        parts.append(f"DMARC({dmarc.get('policy', 'n/a')})")
    if dkim.get("found"):
        parts.append("DKIM")

    detail = f"Email security: {', '.join(parts) if parts else 'none configured'} ({email_score}/100)"

    return {"score": scaled, "max": 20, "detail": detail}


def _score_https(http_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on HTTPS and security headers.
    Max 15 points: HTTPS reachable = 5, headers_score/100*10 = up to 10.
    """
    if not http_data:
        return {"score": 0, "max": 15, "detail": "HTTP data unavailable"}

    score = 0
    parts = []

    if http_data.get("https_reachable"):
        score += 5
        parts.append("HTTPS available")
    else:
        parts.append("No HTTPS")

    headers_score = http_data.get("headers_score", 0)
    header_pts = int((headers_score / 100) * 10)
    score += header_pts
    parts.append(f"Headers score: {headers_score}/100")

    if http_data.get("redirect_to_https"):
        parts.append("HTTP->HTTPS redirect")

    detail = " | ".join(parts)
    return {"score": score, "max": 15, "detail": detail}


def _score_subdomains(subdomain_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on subdomain presence (indicates established infrastructure).
    Max 10 points.
    Penalty if takeover candidates found.
    """
    if not subdomain_data:
        return {"score": 5, "max": 10, "detail": "Subdomain data unavailable"}

    count = subdomain_data.get("total_count", 0)
    takeover = subdomain_data.get("takeover_candidates", [])

    if count >= 10:
        score = 10
        detail = f"{count} subdomains (well established)"
    elif count >= 3:
        score = 7
        detail = f"{count} subdomains found"
    elif count >= 1:
        score = 4
        detail = f"{count} subdomain(s) found"
    else:
        score = 0
        detail = "No subdomains found"

    if takeover:
        penalty = min(10, len(takeover) * 5)
        score = max(0, score - penalty)
        detail += f" | [red]WARNING: {len(takeover)} takeover candidate(s)[/red]"

    return {"score": score, "max": 10, "detail": detail}


def _score_whois_completeness(whois_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on WHOIS data completeness.
    Max 10 points.
    """
    if not whois_data or whois_data.get("error"):
        return {"score": 0, "max": 10, "detail": "WHOIS data unavailable or hidden"}

    score = 0
    fields = []

    if whois_data.get("registrar"):
        score += 3
        fields.append("registrar")
    if whois_data.get("creation_date"):
        score += 3
        fields.append("creation date")
    if whois_data.get("registrant_org") or whois_data.get("registrant"):
        score += 2
        fields.append("registrant")
    if whois_data.get("expiration_date"):
        score += 2
        fields.append("expiry date")

    # Penalty for expiring soon
    days_until_expiry = whois_data.get("days_until_expiry")
    if days_until_expiry is not None and days_until_expiry < 30:
        score = max(0, score - 5)
        fields.append(f"EXPIRING in {days_until_expiry}d!")

    detail = f"WHOIS fields: {', '.join(fields) if fields else 'all hidden (privacy protection)'}"
    return {"score": score, "max": 10, "detail": detail}


def _score_archive(archive_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score based on archive presence.
    Max 5 points. Having old snapshots indicates established domain.
    """
    if not archive_data:
        return {"score": 0, "max": 5, "detail": "Archive data unavailable"}

    if not archive_data.get("available"):
        return {"score": 0, "max": 5, "detail": "No Wayback Machine snapshots found"}

    first_seen = archive_data.get("first_seen")
    if first_seen:
        try:
            year = int(first_seen[:4])
            if year <= 2010:
                score = 5
                detail = f"Archived since {first_seen} (long history)"
            elif year <= 2015:
                score = 4
                detail = f"Archived since {first_seen}"
            elif year <= 2020:
                score = 3
                detail = f"Archived since {first_seen}"
            else:
                score = 2
                detail = f"Archived since {first_seen} (recent)"
        except (ValueError, TypeError):
            score = 2
            detail = "Has archive snapshots"
    else:
        score = 2
        detail = "Has archive snapshots"

    return {"score": score, "max": 5, "detail": detail}


def _build_recommendations(breakdown: Dict[str, Any], whois: Dict, dns: Dict,
                            http: Dict, email: Dict, subdomain: Dict, archive: Dict,
                            ports: Optional[Dict]) -> List[str]:
    """Build actionable security recommendations based on analysis."""
    recs = []

    # Domain age
    if breakdown.get("domain_age", {}).get("score", 25) < 5:
        recs.append("New domain detected - verify legitimacy before trusting")

    # DNS
    dns_score = breakdown.get("dns_completeness", {})
    if dns and not dns.get("mx_records"):
        recs.append("No MX records - domain cannot receive email (may be intentional)")

    # Email security
    if email:
        if not email.get("spf", {}).get("found"):
            recs.append("Add SPF record to prevent email spoofing (v=spf1 ... -all)")
        elif email.get("spf", {}).get("policy") == "pass_all":
            recs.append("CRITICAL: SPF +all allows anyone to send email as your domain - fix immediately")

        if not email.get("dmarc", {}).get("found"):
            recs.append("Add DMARC record (_dmarc.domain TXT) - start with p=none for monitoring")
        elif email.get("dmarc", {}).get("policy") == "none":
            recs.append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")

        if not email.get("dkim", {}).get("found"):
            recs.append("Configure DKIM signing for outbound email")

    # HTTPS
    if http:
        if not http.get("https_reachable"):
            recs.append("Enable HTTPS - obtain TLS certificate (Let's Encrypt is free)")
        else:
            if not http.get("redirect_to_https"):
                recs.append("Configure HTTP to HTTPS redirect")
            if "Strict-Transport-Security" not in http.get("security_headers", {}):
                recs.append("Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains")
            if "Content-Security-Policy" not in http.get("security_headers", {}):
                recs.append("Add Content-Security-Policy header to prevent XSS attacks")
            if "X-Frame-Options" not in http.get("security_headers", {}):
                recs.append("Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking")

        tls = http.get("tls_info", {})
        if tls:
            days = tls.get("days_until_expiry")
            if days is not None and days < 30:
                recs.append(f"TLS certificate expires in {days} days - renew soon!")

    # AXFR
    if dns:
        for axfr in dns.get("axfr_results", []):
            if axfr.get("success"):
                recs.append(f"CRITICAL: DNS zone transfer (AXFR) is enabled on {axfr.get('ns_name')} - disable immediately")

    # Subdomain takeovers
    if subdomain:
        for candidate in subdomain.get("takeover_candidates", []):
            if candidate.get("confirmed"):
                recs.append(f"CRITICAL: Subdomain takeover confirmed on {candidate.get('subdomain')} - remove dangling CNAME")
            else:
                recs.append(f"Potential subdomain takeover risk on {candidate.get('subdomain')} - investigate CNAME to {candidate.get('cname')}")

    # Port scan
    if ports:
        open_ports = ports.get("open_ports", [])
        for port_info in open_ports:
            p = port_info.get("port")
            if p == 23:
                recs.append("Telnet (port 23) is open - disable telnet and use SSH instead")
            elif p == 21:
                recs.append("FTP (port 21) is open - consider using SFTP/FTPS instead")
            elif p == 3389:
                recs.append("RDP (port 3389) is exposed - restrict access with firewall rules")
            elif p == 3306:
                recs.append("MySQL (port 3306) is exposed publicly - restrict to localhost")
            elif p == 5432:
                recs.append("PostgreSQL (port 5432) is exposed publicly - restrict to localhost")

    if not recs:
        recs.append("Security posture looks good! Keep monitoring regularly.")

    return recs


def calculate_risk_score(
    whois: Optional[Dict[str, Any]],
    dns: Optional[Dict[str, Any]],
    http: Optional[Dict[str, Any]],
    geo: Optional[Dict[str, Any]],
    subdomains: Optional[Dict[str, Any]],
    email: Optional[Dict[str, Any]],
    archive: Optional[Dict[str, Any]],
    ports: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Calculate unified risk/trust score for a domain.

    Returns dict with:
      - score: 0-100 (higher = more trusted/established)
      - risk_level: LOW_RISK / MEDIUM_RISK / ELEVATED_RISK / HIGH_RISK
      - risk_label: human readable label
      - breakdown: per-category scores
      - recommendations: list of actionable items
    """
    result: Dict[str, Any] = {
        "score": 0,
        "risk_level": RISK_HIGH,
        "risk_label": RISK_LABELS[RISK_HIGH],
        "breakdown": {},
        "recommendations": [],
    }

    # Calculate each component
    age_result = _score_domain_age(whois or {})
    dns_result = _score_dns_completeness(dns or {})
    email_result = _score_email_security(email or {})
    https_result = _score_https(http or {})
    subdomain_result = _score_subdomains(subdomains or {})
    whois_result = _score_whois_completeness(whois or {})
    archive_result = _score_archive(archive or {})

    breakdown = {
        "domain_age": age_result,
        "dns_completeness": dns_result,
        "email_security": email_result,
        "https_headers": https_result,
        "subdomain_presence": subdomain_result,
        "whois_completeness": whois_result,
        "archive_presence": archive_result,
    }
    result["breakdown"] = breakdown

    # Sum up scores
    total_score = sum(v["score"] for v in breakdown.values())
    total_max = sum(v["max"] for v in breakdown.values())

    # Normalize to 0-100
    if total_max > 0:
        score = int((total_score / total_max) * 100)
    else:
        score = 0

    result["score"] = score

    # Determine risk level
    if score >= 80:
        result["risk_level"] = RISK_LOW
    elif score >= 60:
        result["risk_level"] = RISK_MEDIUM
    elif score >= 40:
        result["risk_level"] = RISK_ELEVATED
    else:
        result["risk_level"] = RISK_HIGH

    result["risk_label"] = RISK_LABELS[result["risk_level"]]

    # Build recommendations
    result["recommendations"] = _build_recommendations(
        breakdown, whois, dns, http, email, subdomains, archive, ports
    )

    return result


def display_score(scoring: Dict[str, Any], domain: str) -> None:
    """Display risk score with rich visual elements."""
    score = scoring.get("score", 0)
    risk_level = scoring.get("risk_level", RISK_HIGH)
    risk_label = scoring.get("risk_label", "Unknown")
    color = RISK_COLORS.get(risk_level, "white")
    breakdown = scoring.get("breakdown", {})
    recommendations = scoring.get("recommendations", [])

    # Score panel
    bar_width = 40
    filled = int((score / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    score_content = (
        f"\n  [{color} bold]Score: {score}/100[/{color} bold]  [{color}]{risk_label}[/{color}]\n"
        f"\n  [{color}]{bar}[/{color}]\n"
    )

    console.print(Panel(
        score_content,
        title=f"[bold cyan]Risk Assessment - {domain}[/bold cyan]",
        border_style=color,
    ))

    # Breakdown table
    breakdown_table = Table(
        title="[bold cyan]Score Breakdown[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=False,
    )
    breakdown_table.add_column("Category", style="cyan", width=25)
    breakdown_table.add_column("Score", style="white", width=10, justify="center")
    breakdown_table.add_column("Max", style="dim", width=6, justify="center")
    breakdown_table.add_column("Detail", style="dim", overflow="fold")

    label_map = {
        "domain_age": "Domain Age",
        "dns_completeness": "DNS Completeness",
        "email_security": "Email Security",
        "https_headers": "HTTPS / Sec Headers",
        "subdomain_presence": "Subdomain Presence",
        "whois_completeness": "WHOIS Completeness",
        "archive_presence": "Archive Presence",
    }

    for key, data in breakdown.items():
        s = data.get("score", 0)
        m = data.get("max", 0)
        detail = data.get("detail", "")
        pct = int((s / m * 100)) if m > 0 else 0

        if pct >= 70:
            score_str = f"[green]{s}[/green]"
        elif pct >= 40:
            score_str = f"[yellow]{s}[/yellow]"
        else:
            score_str = f"[red]{s}[/red]"

        breakdown_table.add_row(
            label_map.get(key, key),
            score_str,
            str(m),
            detail,
        )

    console.print(breakdown_table)

    # Recommendations
    if recommendations:
        rec_table = Table(
            title="[bold yellow]Recommendations[/bold yellow]",
            show_header=True,
            header_style="bold yellow",
            border_style="yellow",
            expand=True,
        )
        rec_table.add_column("#", style="dim", width=4)
        rec_table.add_column("Recommendation", style="white", overflow="fold")

        for i, rec in enumerate(recommendations, 1):
            if rec.startswith("CRITICAL:"):
                rec_table.add_row(str(i), f"[red bold]{rec}[/red bold]")
            elif rec.startswith("WARNING:") or "EXPIRING" in rec or "takeover" in rec.lower():
                rec_table.add_row(str(i), f"[yellow]{rec}[/yellow]")
            else:
                rec_table.add_row(str(i), rec)

        console.print(rec_table)
