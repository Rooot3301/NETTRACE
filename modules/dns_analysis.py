"""
NetTrace v2 - DNS Analysis Module
Performs comprehensive DNS record lookup, zone transfer testing, and DNSSEC checks.
"""
import socket
from typing import Dict, Any, List

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.rdatatype
import dns.name

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import DEFAULT_TIMEOUT

console = Console()


def _resolve_records(domain: str, record_type: str) -> List[str]:
    """Resolve DNS records of a given type for a domain. Returns list of string values."""
    results = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT
        answers = resolver.resolve(domain, record_type)
        for rdata in answers:
            results.append(rdata.to_text())
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.NoRootSOA, Exception):
        pass
    return results


def _try_axfr(ns_host: str, domain: str) -> Dict[str, Any]:
    """
    Attempt DNS zone transfer (AXFR) from a nameserver.
    Returns dict with success bool and records list.
    """
    result = {"ns": ns_host, "success": False, "records": [], "error": "blocked"}
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=DEFAULT_TIMEOUT))
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata.to_text()}")
        result["success"] = True
        result["records"] = records
        result["error"] = None
    except dns.query.TransferError:
        result["error"] = "transfer_refused"
    except dns.exception.FormError:
        result["error"] = "form_error"
    except EOFError:
        result["error"] = "connection_closed"
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


def analyze_dns(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Perform full DNS analysis for a domain.

    Returns dict with:
      - a_records, aaaa_records, mx_records, txt_records, ns_records,
        cname_records, soa_records
      - axfr_results: list of AXFR attempt results
      - dnssec_enabled: bool
      - ips: flat list of IPv4 addresses
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "txt_records": [],
        "ns_records": [],
        "cname_records": [],
        "soa_records": [],
        "axfr_results": [],
        "dnssec_enabled": False,
        "dnskey_records": [],
        "rrsig_records": [],
        "ips": [],
        "error": None,
    }

    try:
        result["a_records"] = _resolve_records(domain, "A")
        result["aaaa_records"] = _resolve_records(domain, "AAAA")
        result["mx_records"] = _resolve_records(domain, "MX")
        result["txt_records"] = _resolve_records(domain, "TXT")
        result["ns_records"] = _resolve_records(domain, "NS")
        result["cname_records"] = _resolve_records(domain, "CNAME")
        result["soa_records"] = _resolve_records(domain, "SOA")

        # Collect IPs from A records
        result["ips"] = result["a_records"]

        # DNSSEC check
        dnskey = _resolve_records(domain, "DNSKEY")
        rrsig = _resolve_records(domain, "RRSIG")
        result["dnskey_records"] = dnskey
        result["rrsig_records"] = rrsig
        result["dnssec_enabled"] = len(dnskey) > 0 or len(rrsig) > 0

        # AXFR zone transfer attempts
        axfr_results = []
        ns_hosts = []
        for ns in result["ns_records"]:
            ns_clean = ns.rstrip(".")
            try:
                ip = socket.gethostbyname(ns_clean)
                ns_hosts.append((ns_clean, ip))
            except socket.gaierror:
                ns_hosts.append((ns_clean, ns_clean))

        for ns_name, ns_addr in ns_hosts[:3]:  # Limit to first 3 NS
            axfr_result = _try_axfr(ns_addr, domain)
            axfr_result["ns_name"] = ns_name
            axfr_results.append(axfr_result)

        result["axfr_results"] = axfr_results

    except Exception as e:
        result["error"] = str(e)

    if verbose:
        _display_dns(result)

    return result


def _display_dns(result: Dict[str, Any]) -> None:
    """Display DNS results using rich tables."""
    domain = result.get("domain", "")

    # Main records table
    table = Table(
        title=f"[bold cyan]DNS Records - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Type", style="cyan", width=10)
    table.add_column("Record(s)", style="white")

    record_types = [
        ("A", result.get("a_records", [])),
        ("AAAA", result.get("aaaa_records", [])),
        ("MX", result.get("mx_records", [])),
        ("NS", result.get("ns_records", [])),
        ("CNAME", result.get("cname_records", [])),
        ("SOA", result.get("soa_records", [])),
        ("TXT", result.get("txt_records", [])),
    ]

    for rtype, records in record_types:
        if records:
            for i, record in enumerate(records):
                if i == 0:
                    table.add_row(rtype, record)
                else:
                    table.add_row("", record)
        else:
            table.add_row(rtype, "[dim]No records found[/dim]")

    console.print(table)

    # DNSSEC status
    dnssec_status = "[green]ENABLED[/green]" if result.get("dnssec_enabled") else "[red]DISABLED[/red]"
    console.print(f"  [bold]DNSSEC:[/bold] {dnssec_status}")

    # AXFR results
    axfr_results = result.get("axfr_results", [])
    if axfr_results:
        axfr_table = Table(
            title="[bold cyan]Zone Transfer (AXFR) Tests[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
        )
        axfr_table.add_column("Nameserver", style="cyan")
        axfr_table.add_column("Status", style="white")
        axfr_table.add_column("Records", style="white")

        for axfr in axfr_results:
            ns_name = axfr.get("ns_name", axfr.get("ns", ""))
            if axfr.get("success"):
                status = "[red bold]VULNERABLE - AXFR SUCCESS[/red bold]"
                record_count = str(len(axfr.get("records", [])))
            else:
                error = axfr.get("error", "blocked")
                status = f"[green]Blocked[/green] ({error})"
                record_count = "0"
            axfr_table.add_row(ns_name, status, record_count)

        console.print(axfr_table)
