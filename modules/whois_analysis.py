"""
NetTrace v2 - WHOIS Analysis Module
Performs WHOIS lookups with robust date parsing and rich display.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

import whois
from dateutil import parser as dateutil_parser

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def _parse_date(date_val) -> Optional[datetime]:
    """
    Robustly parse a date from various formats returned by python-whois.
    Returns timezone-aware datetime or None.
    """
    if date_val is None:
        return None
    # Handle list (some registrars return multiple dates)
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if date_val is None:
        return None
    # Already a datetime
    if isinstance(date_val, datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=timezone.utc)
        return date_val
    # String - try dateutil
    if isinstance(date_val, str):
        try:
            parsed = dateutil_parser.parse(date_val)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, OverflowError):
            return None
    return None


def _extract_str(val) -> str:
    """Extract string from possibly list/None values."""
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else ""
    return str(val).strip()


def analyze_whois(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Perform WHOIS analysis for a domain.

    Returns dict with:
      - registrar, creation_date, expiration_date, updated_date
      - registrant, status, name_servers, age_days, days_until_expiry
      - raw (raw whois text)
      - error
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "registrar": "",
        "registrar_url": "",
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrant": "",
        "registrant_org": "",
        "registrant_country": "",
        "status": [],
        "name_servers": [],
        "age_days": None,
        "days_until_expiry": None,
        "dnssec": "",
        "emails": [],
        "error": None,
    }

    try:
        w = whois.whois(domain)

        result["registrar"] = _extract_str(getattr(w, "registrar", None))
        result["registrar_url"] = _extract_str(getattr(w, "registrar_url", None))

        creation = _parse_date(getattr(w, "creation_date", None))
        expiration = _parse_date(getattr(w, "expiration_date", None))
        updated = _parse_date(getattr(w, "updated_date", None))

        now = datetime.now(timezone.utc)

        result["creation_date"] = creation.isoformat() if creation else None
        result["expiration_date"] = expiration.isoformat() if expiration else None
        result["updated_date"] = updated.isoformat() if updated else None

        if creation:
            result["age_days"] = (now - creation).days

        if expiration:
            result["days_until_expiry"] = (expiration - now).days

        # Registrant info
        result["registrant"] = _extract_str(getattr(w, "name", None))
        result["registrant_org"] = _extract_str(getattr(w, "org", None))
        result["registrant_country"] = _extract_str(getattr(w, "country", None))

        # Status
        status = getattr(w, "status", None)
        if status is None:
            result["status"] = []
        elif isinstance(status, list):
            result["status"] = [str(s) for s in status]
        else:
            result["status"] = [str(status)]

        # Name servers
        ns = getattr(w, "name_servers", None)
        if ns is None:
            result["name_servers"] = []
        elif isinstance(ns, list):
            result["name_servers"] = [str(n).lower().rstrip(".") for n in ns]
        else:
            result["name_servers"] = [str(ns).lower().rstrip(".")]

        # Emails
        emails = getattr(w, "emails", None)
        if emails is None:
            result["emails"] = []
        elif isinstance(emails, list):
            result["emails"] = [str(e) for e in emails]
        else:
            result["emails"] = [str(emails)]

        result["dnssec"] = _extract_str(getattr(w, "dnssec", None))

    except Exception as e:
        result["error"] = str(e)

    if verbose:
        _display_whois(result)

    return result


def _display_whois(result: Dict[str, Any]) -> None:
    """Display WHOIS results using rich panels and tables."""
    domain = result.get("domain", "")

    table = Table(
        title=f"[bold cyan]WHOIS Information - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Field", style="cyan", width=22)
    table.add_column("Value", style="white")

    def fmt_date(iso_str):
        if not iso_str:
            return "[dim]N/A[/dim]"
        try:
            dt = datetime.fromisoformat(iso_str)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            return iso_str

    age_days = result.get("age_days")
    age_str = f"{age_days} days ({age_days // 365} years)" if age_days is not None else "[dim]N/A[/dim]"

    exp_days = result.get("days_until_expiry")
    if exp_days is not None:
        if exp_days < 0:
            exp_str = f"[red bold]EXPIRED {abs(exp_days)} days ago[/red bold]"
        elif exp_days < 30:
            exp_str = f"[red]{exp_days} days (EXPIRING SOON)[/red]"
        elif exp_days < 90:
            exp_str = f"[yellow]{exp_days} days[/yellow]"
        else:
            exp_str = f"[green]{exp_days} days[/green]"
    else:
        exp_str = "[dim]N/A[/dim]"

    rows = [
        ("Registrar", result.get("registrar") or "[dim]N/A[/dim]"),
        ("Registrar URL", result.get("registrar_url") or "[dim]N/A[/dim]"),
        ("Created", fmt_date(result.get("creation_date"))),
        ("Expires", fmt_date(result.get("expiration_date"))),
        ("Last Updated", fmt_date(result.get("updated_date"))),
        ("Domain Age", age_str),
        ("Days Until Expiry", exp_str),
        ("Registrant", result.get("registrant") or "[dim]N/A[/dim]"),
        ("Organization", result.get("registrant_org") or "[dim]N/A[/dim]"),
        ("Country", result.get("registrant_country") or "[dim]N/A[/dim]"),
        ("DNSSEC", result.get("dnssec") or "[dim]N/A[/dim]"),
    ]

    for field, value in rows:
        table.add_row(field, str(value))

    # Status list
    status_list = result.get("status", [])
    if status_list:
        status_str = "\n".join(status_list[:5])
        if len(status_list) > 5:
            status_str += f"\n... and {len(status_list) - 5} more"
        table.add_row("Status", status_str)

    # Name servers
    ns_list = result.get("name_servers", [])
    if ns_list:
        table.add_row("Name Servers", "\n".join(ns_list[:6]))

    console.print(table)
