"""
NetTrace v2 - Email Security Analysis Module
Checks SPF, DMARC, DKIM, BIMI, and MTA-STS records for a domain.
"""
from typing import Dict, Any, List, Optional

import dns.resolver
import dns.exception

from rich.console import Console
from rich.table import Table

from config import DEFAULT_TIMEOUT

console = Console()

# Common DKIM selectors to test
DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "selector1", "selector2",
    "dkim", "email", "smtp", "s1", "s2", "key1", "key2",
    "mx", "protonmail", "fm1", "fm2", "fm3",
]


def _resolve_txt(name: str) -> List[str]:
    """Resolve TXT records for a DNS name. Returns list of record strings."""
    records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT
        answers = resolver.resolve(name, "TXT")
        for rdata in answers:
            record_str = " ".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            records.append(record_str)
    except Exception:
        pass
    return records


def _analyze_spf(txt_records: List[str]) -> Dict[str, Any]:
    """
    Analyze SPF record from existing TXT records.
    Returns dict with: found, record, policy, mechanisms, all_qualifier, score.
    """
    result: Dict[str, Any] = {
        "found": False,
        "record": None,
        "policy": None,
        "mechanisms": [],
        "all_qualifier": None,
        "valid": False,
        "issues": [],
    }

    spf_record = None
    for txt in txt_records:
        if txt.strip().startswith("v=spf1"):
            spf_record = txt.strip()
            break

    if not spf_record:
        result["issues"].append("No SPF record found")
        return result

    result["found"] = True
    result["record"] = spf_record
    result["valid"] = True

    parts = spf_record.split()
    mechanisms = []
    all_qualifier = None

    for part in parts[1:]:  # skip v=spf1
        if part.lower() in ("+all", "-all", "~all", "?all"):
            all_qualifier = part.lower()
        elif part.lower() == "all":
            all_qualifier = "+all"
        else:
            mechanisms.append(part)

    result["mechanisms"] = mechanisms
    result["all_qualifier"] = all_qualifier

    # Determine policy
    if all_qualifier == "-all":
        result["policy"] = "fail"  # Good - rejects unauthorized
    elif all_qualifier == "~all":
        result["policy"] = "softfail"  # Acceptable
    elif all_qualifier == "?all":
        result["policy"] = "neutral"  # Weak
    elif all_qualifier == "+all":
        result["policy"] = "pass_all"  # BAD - allows anyone
        result["issues"].append("+all qualifier allows any sender - misconfiguration!")
    else:
        result["policy"] = "no_all"
        result["issues"].append("No 'all' qualifier - incomplete SPF record")

    return result


def _analyze_dmarc(domain: str) -> Dict[str, Any]:
    """
    Fetch and analyze DMARC record for domain.
    Returns dict with: found, record, policy, subdomain_policy, pct, rua, ruf.
    """
    result: Dict[str, Any] = {
        "found": False,
        "record": None,
        "policy": None,
        "subdomain_policy": None,
        "pct": 100,
        "rua": None,
        "ruf": None,
        "issues": [],
    }

    dmarc_records = _resolve_txt(f"_dmarc.{domain}")

    dmarc_record = None
    for rec in dmarc_records:
        if "v=dmarc1" in rec.lower():
            dmarc_record = rec
            break

    if not dmarc_record:
        result["issues"].append("No DMARC record found")
        return result

    result["found"] = True
    result["record"] = dmarc_record

    # Parse DMARC tags
    tags = {}
    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            tags[key.strip().lower()] = val.strip()

    policy = tags.get("p", "none")
    result["policy"] = policy

    sp = tags.get("sp")
    result["subdomain_policy"] = sp if sp else policy

    try:
        result["pct"] = int(tags.get("pct", "100"))
    except ValueError:
        result["pct"] = 100

    result["rua"] = tags.get("rua")
    result["ruf"] = tags.get("ruf")

    # Issue checks
    if policy == "none":
        result["issues"].append("DMARC policy is 'none' - no enforcement")
    elif policy == "quarantine":
        pass  # Acceptable
    elif policy == "reject":
        pass  # Best

    if result["pct"] < 100:
        result["issues"].append(f"DMARC pct={result['pct']}% - not enforcing on all mail")

    if not result["rua"]:
        result["issues"].append("No DMARC aggregate reporting (rua) configured")

    return result


def _analyze_dkim(domain: str) -> Dict[str, Any]:
    """
    Check common DKIM selectors for the domain.
    Returns dict with: found_selectors list, records dict.
    """
    result: Dict[str, Any] = {
        "found": False,
        "found_selectors": [],
        "records": {},
        "issues": [],
    }

    found = []
    records_map = {}

    for selector in DKIM_SELECTORS:
        dkim_name = f"{selector}._domainkey.{domain}"
        txt_records = _resolve_txt(dkim_name)
        for rec in txt_records:
            if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                found.append(selector)
                # Truncate public key for display
                short_rec = rec[:120] + "..." if len(rec) > 120 else rec
                records_map[selector] = short_rec
                break

    result["found"] = len(found) > 0
    result["found_selectors"] = found
    result["records"] = records_map

    if not found:
        result["issues"].append("No DKIM records found for common selectors")

    return result


def _analyze_bimi(domain: str) -> Dict[str, Any]:
    """Check for BIMI record."""
    result: Dict[str, Any] = {
        "found": False,
        "record": None,
    }
    records = _resolve_txt(f"default._bimi.{domain}")
    for rec in records:
        if "v=bimi1" in rec.lower():
            result["found"] = True
            result["record"] = rec
            break
    return result


def _analyze_mta_sts(domain: str) -> Dict[str, Any]:
    """Check for MTA-STS record."""
    result: Dict[str, Any] = {
        "found": False,
        "record": None,
        "version": None,
        "id": None,
    }
    records = _resolve_txt(f"_mta-sts.{domain}")
    for rec in records:
        if "v=sts1" in rec.lower():
            result["found"] = True
            result["record"] = rec
            # Parse id
            for part in rec.split(";"):
                part = part.strip()
                if part.lower().startswith("id="):
                    result["id"] = part[3:]
                elif part.lower().startswith("v="):
                    result["version"] = part[2:]
            break
    return result


def _calculate_email_score(spf: Dict, dmarc: Dict, dkim: Dict, bimi: Dict, mta_sts: Dict) -> int:
    """
    Calculate email security score 0-100.
    SPF: 25pts, DMARC: 35pts, DKIM: 25pts, BIMI: 5pts, MTA-STS: 10pts
    """
    score = 0

    # SPF scoring (25 pts)
    if spf.get("found"):
        policy = spf.get("policy")
        if policy == "fail":
            score += 25
        elif policy == "softfail":
            score += 20
        elif policy == "neutral":
            score += 10
        elif policy == "pass_all":
            score += 5  # Bad config
        else:
            score += 15  # No 'all' but has SPF

    # DMARC scoring (35 pts)
    if dmarc.get("found"):
        policy = dmarc.get("policy", "none")
        if policy == "reject":
            score += 35
        elif policy == "quarantine":
            score += 25
        elif policy == "none":
            score += 10
        # Bonus for reporting
        if dmarc.get("rua"):
            score += 0  # Already included above

    # DKIM scoring (25 pts)
    if dkim.get("found"):
        score += 25

    # BIMI (5 pts - indicates strong email security setup)
    if bimi.get("found"):
        score += 5

    # MTA-STS (10 pts)
    if mta_sts.get("found"):
        score += 10

    return min(100, score)


def analyze_email_security(domain: str, dns_records: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """
    Perform complete email security analysis.

    Returns dict with:
      - spf, dmarc, dkim, bimi, mta_sts: individual analysis dicts
      - email_score: 0-100
      - issues: consolidated list of issues
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "spf": {},
        "dmarc": {},
        "dkim": {},
        "bimi": {},
        "mta_sts": {},
        "email_score": 0,
        "issues": [],
        "error": None,
    }

    try:
        # Get TXT records from DNS analysis or re-resolve
        txt_records = dns_records.get("txt_records", []) if dns_records else []
        if not txt_records:
            from modules.dns_analysis import _resolve_records
            txt_records = _resolve_records(domain, "TXT")

        spf = _analyze_spf(txt_records)
        dmarc = _analyze_dmarc(domain)
        dkim = _analyze_dkim(domain)
        bimi = _analyze_bimi(domain)
        mta_sts = _analyze_mta_sts(domain)

        result["spf"] = spf
        result["dmarc"] = dmarc
        result["dkim"] = dkim
        result["bimi"] = bimi
        result["mta_sts"] = mta_sts

        # Consolidated issues
        all_issues = []
        all_issues.extend(spf.get("issues", []))
        all_issues.extend(dmarc.get("issues", []))
        all_issues.extend(dkim.get("issues", []))
        result["issues"] = all_issues

        result["email_score"] = _calculate_email_score(spf, dmarc, dkim, bimi, mta_sts)

    except Exception as e:
        result["error"] = str(e)

    if verbose:
        _display_email_security(result)

    return result


def _display_email_security(result: Dict[str, Any]) -> None:
    """Display email security results with rich table."""
    domain = result.get("domain", "")

    table = Table(
        title=f"[bold cyan]Email Security Analysis - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Check", style="cyan", width=18)
    table.add_column("Status", style="white", width=14)
    table.add_column("Policy / Value", style="white", width=22)
    table.add_column("Details", style="dim", overflow="fold")

    spf = result.get("spf", {})
    dmarc = result.get("dmarc", {})
    dkim = result.get("dkim", {})
    bimi = result.get("bimi", {})
    mta_sts = result.get("mta_sts", {})

    # SPF
    if spf.get("found"):
        spf_policy = spf.get("policy", "unknown")
        if spf_policy == "fail":
            spf_status = "[green]Configured[/green]"
            policy_str = "[green]-all (strict)[/green]"
        elif spf_policy == "softfail":
            spf_status = "[yellow]Configured[/yellow]"
            policy_str = "[yellow]~all (soft)[/yellow]"
        elif spf_policy == "pass_all":
            spf_status = "[red]Misconfigured[/red]"
            policy_str = "[red]+all (FAIL)[/red]"
        else:
            spf_status = "[yellow]Partial[/yellow]"
            policy_str = spf_policy
        details = f"{len(spf.get('mechanisms', []))} mechanism(s)"
    else:
        spf_status = "[red]Missing[/red]"
        policy_str = "N/A"
        details = "No SPF record"

    table.add_row("SPF", spf_status, policy_str, details)

    # DMARC
    if dmarc.get("found"):
        dmarc_policy = dmarc.get("policy", "none")
        if dmarc_policy == "reject":
            dmarc_status = "[green]Configured[/green]"
            dmarc_policy_str = "[green]reject[/green]"
        elif dmarc_policy == "quarantine":
            dmarc_status = "[yellow]Configured[/yellow]"
            dmarc_policy_str = "[yellow]quarantine[/yellow]"
        else:
            dmarc_status = "[red]Weak[/red]"
            dmarc_policy_str = "[red]none[/red]"
        pct = dmarc.get("pct", 100)
        rua = dmarc.get("rua", "")
        details = f"pct={pct}%" + (f", rua={rua[:40]}" if rua else ", no rua")
    else:
        dmarc_status = "[red]Missing[/red]"
        dmarc_policy_str = "N/A"
        details = "No DMARC record"

    table.add_row("DMARC", dmarc_status, dmarc_policy_str, details)

    # DKIM
    if dkim.get("found"):
        selectors = dkim.get("found_selectors", [])
        dkim_status = "[green]Found[/green]"
        dkim_val = f"Selectors: {', '.join(selectors[:4])}"
        details = f"{len(selectors)} selector(s) found"
    else:
        dkim_status = "[red]Not found[/red]"
        dkim_val = "No common selectors"
        details = "Checked: " + ", ".join(DKIM_SELECTORS[:8]) + "..."

    table.add_row("DKIM", dkim_status, dkim_val, details)

    # BIMI
    bimi_status = "[green]Present[/green]" if bimi.get("found") else "[dim]Not configured[/dim]"
    table.add_row("BIMI", bimi_status, "Brand Indicator", "" if not bimi.get("found") else "Logo configured")

    # MTA-STS
    if mta_sts.get("found"):
        mta_status = "[green]Present[/green]"
        mta_val = f"ID: {mta_sts.get('id', 'N/A')}"
    else:
        mta_status = "[dim]Not configured[/dim]"
        mta_val = ""
    table.add_row("MTA-STS", mta_status, mta_val, "")

    console.print(table)

    # Score
    score = result.get("email_score", 0)
    if score >= 80:
        score_str = f"[green bold]{score}/100[/green bold]"
    elif score >= 50:
        score_str = f"[yellow bold]{score}/100[/yellow bold]"
    else:
        score_str = f"[red bold]{score}/100[/red bold]"

    console.print(f"  [bold]Email Security Score:[/bold] {score_str}")

    # Issues
    issues = result.get("issues", [])
    if issues:
        console.print("  [yellow]Issues:[/yellow]")
        for issue in issues:
            console.print(f"    [yellow]- {issue}[/yellow]")
