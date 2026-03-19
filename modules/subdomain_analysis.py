"""
NetTrace v2 - Subdomain Enumeration and Takeover Detection Module
Sources: crt.sh, subfinder (optional), amass (optional).
Detects potential subdomain takeover via CNAME fingerprinting.
"""
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Set

import requests
import requests.exceptions
import dns.resolver
import dns.exception

from rich.console import Console
from rich.table import Table

from config import DEFAULT_TIMEOUT, TAKEOVER_FINGERPRINTS

console = Console()

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


def _fetch_crtsh(domain: str) -> Set[str]:
    """Fetch subdomains from crt.sh Certificate Transparency logs."""
    subdomains: Set[str] = set()
    try:
        resp = requests.get(
            CRTSH_URL.format(domain=domain),
            timeout=DEFAULT_TIMEOUT * 2,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    subdomain = line.strip().lower().lstrip("*.")
                    if subdomain and "." in subdomain:
                        subdomains.add(subdomain)
    except Exception:
        pass
    return subdomains


def _run_tool(tool: str, domain: str) -> Set[str]:
    """Run subfinder or amass if available, return set of subdomains."""
    subdomains: Set[str] = set()
    if not shutil.which(tool):
        return subdomains

    try:
        if tool == "subfinder":
            cmd = ["subfinder", "-d", domain, "-silent", "-timeout", "30"]
        elif tool == "amass":
            cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "60"]
        else:
            return subdomains

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        for line in proc.stdout.splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                subdomains.add(sub)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return subdomains


def _get_cname(subdomain: str) -> Optional[str]:
    """Resolve CNAME record for a subdomain. Returns CNAME target or None."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT
        answers = resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return rdata.target.to_text().rstrip(".")
    except Exception:
        pass
    return None


def _resolves(subdomain: str) -> bool:
    """Check if a subdomain resolves (has any A/AAAA record)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.resolve(subdomain, "A")
        return True
    except Exception:
        pass
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.resolve(subdomain, "AAAA")
        return True
    except Exception:
        pass
    return False


def _check_takeover(subdomain: str, cname: str) -> Optional[Dict[str, Any]]:
    """
    Check if a subdomain with a CNAME is vulnerable to takeover.
    Returns dict with details if potentially vulnerable, else None.
    """
    for pattern, fingerprint in TAKEOVER_FINGERPRINTS.items():
        if pattern.lower() in cname.lower():
            # Try HTTP GET to confirm vulnerability
            try:
                resp = requests.get(
                    f"https://{subdomain}",
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
                )
                if fingerprint.lower() in resp.text.lower():
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": pattern,
                        "fingerprint": fingerprint,
                        "http_status": resp.status_code,
                        "confirmed": True,
                    }
                # Even if body doesn't match, flag as candidate
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": pattern,
                    "fingerprint": fingerprint,
                    "http_status": resp.status_code,
                    "confirmed": False,
                }
            except Exception:
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": pattern,
                    "fingerprint": fingerprint,
                    "http_status": None,
                    "confirmed": False,
                }
    return None


def analyze_subdomains(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Enumerate subdomains from multiple sources and check for takeover vulnerabilities.

    Returns dict with:
      - subdomains: list of all discovered subdomains
      - sources: dict mapping source -> count
      - takeover_candidates: list of potential takeover targets
      - total_count: int
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "sources": {},
        "takeover_candidates": [],
        "total_count": 0,
        "error": None,
    }

    all_subdomains: Set[str] = set()

    # Source 1: crt.sh
    crtsh_subs = _fetch_crtsh(domain)
    # Filter to actual subdomains of the target domain
    crtsh_filtered = {s for s in crtsh_subs if s.endswith(f".{domain}") or s == domain}
    all_subdomains |= crtsh_filtered
    result["sources"]["crt.sh"] = len(crtsh_filtered)

    # Source 2: subfinder
    subfinder_subs = _run_tool("subfinder", domain)
    subfinder_filtered = {s for s in subfinder_subs if s.endswith(f".{domain}") or s == domain}
    new_from_subfinder = subfinder_filtered - all_subdomains
    all_subdomains |= subfinder_filtered
    result["sources"]["subfinder"] = len(new_from_subfinder)

    # Source 3: amass
    amass_subs = _run_tool("amass", domain)
    amass_filtered = {s for s in amass_subs if s.endswith(f".{domain}") or s == domain}
    new_from_amass = amass_filtered - all_subdomains
    all_subdomains |= amass_filtered
    result["sources"]["amass"] = len(new_from_amass)

    sorted_subs = sorted(all_subdomains)
    result["subdomains"] = sorted_subs
    result["total_count"] = len(sorted_subs)

    # Takeover detection
    takeover_candidates = []
    # Limit checks to prevent excessive requests
    check_limit = min(len(sorted_subs), 100)
    for subdomain in sorted_subs[:check_limit]:
        cname = _get_cname(subdomain)
        if cname:
            candidate = _check_takeover(subdomain, cname)
            if candidate:
                takeover_candidates.append(candidate)

    result["takeover_candidates"] = takeover_candidates

    if verbose:
        _display_subdomains(result)

    return result


def _display_subdomains(result: Dict[str, Any]) -> None:
    """Display subdomain results with rich tables."""
    domain = result.get("domain", "")
    subdomains = result.get("subdomains", [])
    sources = result.get("sources", {})
    takeover_candidates = result.get("takeover_candidates", [])

    # Sources summary
    source_table = Table(
        title=f"[bold cyan]Subdomain Enumeration - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
    )
    source_table.add_column("Source", style="cyan")
    source_table.add_column("Found", style="white", justify="right")

    total = 0
    for src, count in sources.items():
        source_table.add_row(src, str(count))
        total += count

    source_table.add_row("[bold]Total Unique[/bold]", f"[bold]{result.get('total_count', 0)}[/bold]")
    console.print(source_table)

    # Subdomain list (truncated if large)
    if subdomains:
        display_count = min(len(subdomains), 50)
        sub_table = Table(
            title=f"[bold cyan]Discovered Subdomains (showing {display_count}/{len(subdomains)})[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            expand=True,
        )
        sub_table.add_column("#", style="dim", width=5)
        sub_table.add_column("Subdomain", style="white")

        for i, sub in enumerate(subdomains[:display_count], 1):
            sub_table.add_row(str(i), sub)

        console.print(sub_table)

    # Takeover candidates
    if takeover_candidates:
        takeover_table = Table(
            title="[bold red]Potential Subdomain Takeover Candidates![/bold red]",
            show_header=True,
            header_style="bold red",
            border_style="red",
            expand=True,
        )
        takeover_table.add_column("Subdomain", style="yellow")
        takeover_table.add_column("CNAME Target", style="white")
        takeover_table.add_column("Service", style="cyan")
        takeover_table.add_column("Confirmed", style="red")

        for candidate in takeover_candidates:
            confirmed = "[red bold]YES[/red bold]" if candidate.get("confirmed") else "[yellow]Possible[/yellow]"
            takeover_table.add_row(
                candidate.get("subdomain", ""),
                candidate.get("cname", ""),
                candidate.get("service", ""),
                confirmed,
            )

        console.print(takeover_table)
    else:
        console.print("  [green]No subdomain takeover candidates found.[/green]")
