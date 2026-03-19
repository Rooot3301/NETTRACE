"""
NetTrace v2 - GeoIP Analysis Module
Queries ip-api.com for geolocation and ASN info per IP.
Detects CDN presence based on organization names.
"""
import time
from typing import Dict, Any, List, Optional

import requests
import requests.exceptions

from rich.console import Console
from rich.table import Table

from config import DEFAULT_TIMEOUT, CDN_SIGNATURES

console = Console()

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,hosting,query"

# Delay between requests to respect ip-api rate limit (45 req/min)
IPAPI_DELAY = 0.5


def _is_cdn_org(org: str, isp: str, asname: str) -> Optional[str]:
    """Check if an org/ISP/ASN name matches a known CDN provider."""
    combined = f"{org} {isp} {asname}".lower()
    for cdn_name, patterns in CDN_SIGNATURES.items():
        for pattern in patterns:
            if pattern.lower() in combined:
                return cdn_name
    return None


def _query_ipapi(ip: str) -> Dict[str, Any]:
    """Query ip-api.com for a single IP address."""
    result: Dict[str, Any] = {
        "ip": ip,
        "status": "error",
        "country": "",
        "countryCode": "",
        "region": "",
        "city": "",
        "org": "",
        "isp": "",
        "as": "",
        "asname": "",
        "hosting": False,
        "lat": None,
        "lon": None,
        "timezone": "",
        "cdn": None,
        "error": None,
    }
    try:
        resp = requests.get(
            IPAPI_URL.format(ip=ip),
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        data = resp.json()
        if data.get("status") == "success":
            result["status"] = "success"
            result["country"] = data.get("country", "")
            result["countryCode"] = data.get("countryCode", "")
            result["region"] = data.get("regionName", "")
            result["city"] = data.get("city", "")
            result["org"] = data.get("org", "")
            result["isp"] = data.get("isp", "")
            result["as"] = data.get("as", "")
            result["asname"] = data.get("asname", "")
            result["hosting"] = data.get("hosting", False)
            result["lat"] = data.get("lat")
            result["lon"] = data.get("lon")
            result["timezone"] = data.get("timezone", "")
            # CDN detection
            result["cdn"] = _is_cdn_org(
                result["org"],
                result["isp"],
                result["asname"]
            )
        else:
            result["error"] = data.get("message", "API error")
    except requests.exceptions.Timeout:
        result["error"] = "Request timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


def analyze_geo(domain: str, ips: List[str], verbose: bool = False) -> Dict[str, Any]:
    """
    Perform GeoIP analysis for a list of IPs.

    Returns dict with:
      - ip_info: list of geo info per IP
      - unique_countries: list
      - unique_asns: list
      - is_behind_cdn: bool
      - detected_cdn: first CDN name found or None
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "ip_info": [],
        "unique_countries": [],
        "unique_asns": [],
        "is_behind_cdn": False,
        "detected_cdn": None,
        "error": None,
    }

    if not ips:
        result["error"] = "No IPs provided"
        return result

    ip_info_list = []
    countries = set()
    asns = set()
    cdn_detected = None
    is_cdn = False

    for i, ip in enumerate(ips):
        if i > 0:
            time.sleep(IPAPI_DELAY)
        info = _query_ipapi(ip)
        ip_info_list.append(info)

        if info.get("status") == "success":
            if info.get("country"):
                countries.add(info["country"])
            if info.get("as"):
                asns.add(info["as"])
            if info.get("cdn"):
                is_cdn = True
                cdn_detected = info["cdn"]

    result["ip_info"] = ip_info_list
    result["unique_countries"] = sorted(list(countries))
    result["unique_asns"] = sorted(list(asns))
    result["is_behind_cdn"] = is_cdn
    result["detected_cdn"] = cdn_detected

    if verbose:
        _display_geo(result)

    return result


def _display_geo(result: Dict[str, Any]) -> None:
    """Display GeoIP results with rich table."""
    domain = result.get("domain", "")

    table = Table(
        title=f"[bold cyan]GeoIP Analysis - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    table.add_column("IP Address", style="cyan", width=18)
    table.add_column("Country", style="white", width=18)
    table.add_column("City", style="white", width=16)
    table.add_column("ASN", style="yellow", width=14)
    table.add_column("Organization", style="white")
    table.add_column("CDN", style="green", width=20)
    table.add_column("Hosting", style="dim", width=8)

    for info in result.get("ip_info", []):
        if info.get("status") == "success":
            flag = info.get("countryCode", "")
            country = f"{flag} {info.get('country', '')}"
            cdn_val = info.get("cdn") or ""
            cdn_str = f"[green]{cdn_val}[/green]" if cdn_val else "[dim]No[/dim]"
            hosting_str = "[yellow]Yes[/yellow]" if info.get("hosting") else "[dim]No[/dim]"
            asn = info.get("as", "")
            if len(asn) > 12:
                asn = asn[:12] + "..."
            table.add_row(
                info.get("ip", ""),
                country,
                info.get("city", ""),
                asn,
                info.get("org", "") or info.get("isp", ""),
                cdn_str,
                hosting_str,
            )
        else:
            table.add_row(
                info.get("ip", ""),
                "[red]Error[/red]",
                "",
                "",
                info.get("error", ""),
                "",
                "",
            )

    console.print(table)

    # Summary
    if result.get("is_behind_cdn"):
        console.print(f"  [bold green]CDN Detected: {result.get('detected_cdn')}[/bold green]")
    console.print(f"  Countries: {', '.join(result.get('unique_countries', [])) or 'N/A'}")
    console.print(f"  ASNs: {', '.join(result.get('unique_asns', [])) or 'N/A'}")
