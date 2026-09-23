"""
NetTrace v2 - Wayback Machine Archive Analysis Module
Queries the Wayback Machine CDX API for historical snapshots and interesting URLs.
"""
from typing import Dict, Any, List, Optional

import requests
import requests.exceptions

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import DEFAULT_TIMEOUT

console = Console()

CDX_URL = "http://web.archive.org/cdx/search/cdx"
AVAILABILITY_URL = "http://archive.org/wayback/available"

# Patterns for "interesting" URLs that may reveal sensitive info
INTERESTING_PATTERNS = [
    "/admin", "/administrator", "/login", "/signin", "/sign-in",
    "/api/", "/v1/", "/v2/", "/graphql", "/swagger",
    "/.git", "/.svn", "/.env", "/.htaccess", "/.htpasswd",
    "/backup", "/bak", "/old", "/temp", "/tmp",
    "/config", "/configuration", "/settings",
    "/phpinfo", "/info.php", "/test.php",
    "/wp-admin", "/wp-login", "/wp-config",
    "/phpmyadmin", "/mysql", "/database",
    "password", "passwd", "credentials", "secret", "token",
    ".sql", ".bak", ".backup", ".tar.gz", ".zip", ".dump",
    "/debug", "/console", "/shell",
    "/xmlrpc.php", "/readme.html", "/license.txt",
]


def _is_interesting_url(url: str) -> bool:
    """Check if a URL matches interesting patterns."""
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in INTERESTING_PATTERNS)


def _fetch_cdx_snapshots(domain: str, limit: int = 50) -> List[Dict[str, str]]:
    """
    Fetch snapshots from Wayback Machine CDX API.
    Returns list of {timestamp, url, statuscode} dicts.
    """
    snapshots = []
    try:
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "limit": limit,
            "fl": "timestamp,original,statuscode",
            "collapse": "timestamp:6",  # Collapse by year-month
            "from": "",
            "to": "",
        }
        resp = requests.get(
            CDX_URL,
            params=params,
            timeout=DEFAULT_TIMEOUT * 2,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data and len(data) > 1:
                # First row is header
                keys = data[0]
                for row in data[1:]:
                    if len(row) == len(keys):
                        entry = dict(zip(keys, row))
                        snapshots.append(entry)
    except Exception:
        pass
    return snapshots


def _fetch_total_count(domain: str) -> Optional[int]:
    """
    Get approximate total number of archived snapshots for domain.
    """
    try:
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "limit": 1,
            "fl": "timestamp",
            "showNumPages": "true",
        }
        resp = requests.get(
            CDX_URL,
            params=params,
            timeout=DEFAULT_TIMEOUT * 2,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp.status_code == 200:
            text = resp.text.strip()
            # Response may be a number when showNumPages=true
            try:
                pages = int(text)
                return pages * 1  # each page = 1 result in our case
            except ValueError:
                pass
        # Fallback: try a high-limit count
        params2 = {
            "url": domain,
            "output": "json",
            "limit": 1,
            "fl": "timestamp",
            "matchType": "domain",
        }
        resp2 = requests.get(
            CDX_URL,
            params=params2,
            timeout=DEFAULT_TIMEOUT * 2,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp2.status_code == 200:
            data = resp2.json()
            if data:
                return len(data) - 1  # subtract header
    except Exception:
        pass
    return None


def _fetch_all_urls_for_interesting(domain: str) -> List[str]:
    """
    Fetch a broad set of archived URLs to find interesting ones.
    """
    urls = []
    try:
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "limit": 200,
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
        }
        resp = requests.get(
            CDX_URL,
            params=params,
            timeout=DEFAULT_TIMEOUT * 3,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data and len(data) > 1:
                for row in data[1:]:
                    if row:
                        urls.append(row[0])
    except Exception:
        pass
    return urls


def _check_availability(domain: str) -> Optional[Dict[str, Any]]:
    """
    Check if Wayback Machine has a snapshot for the domain.
    """
    try:
        resp = requests.get(
            AVAILABILITY_URL,
            params={"url": domain},
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            snap = data.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                return {
                    "available": True,
                    "url": snap.get("url", ""),
                    "timestamp": snap.get("timestamp", ""),
                    "status": snap.get("status", ""),
                }
    except Exception:
        pass
    return None


def _format_timestamp(ts: str) -> str:
    """Convert CDX timestamp (YYYYMMDDHHmmss) to readable date."""
    if not ts or len(ts) < 8:
        return ts
    try:
        year = ts[0:4]
        month = ts[4:6]
        day = ts[6:8]
        return f"{year}-{month}-{day}"
    except (IndexError, ValueError):
        return ts


def analyze_archive(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze Wayback Machine archive presence for a domain.

    Returns dict with:
      - available: bool
      - first_seen: date string
      - last_seen: date string
      - snapshot_count: int (approximate)
      - interesting_urls: list of potentially sensitive archived URLs
      - wayback_url: direct URL to latest snapshot
      - snapshots_sample: list of recent snapshots
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "available": False,
        "first_seen": None,
        "last_seen": None,
        "snapshot_count": None,
        "interesting_urls": [],
        "wayback_url": None,
        "snapshots_sample": [],
        "error": None,
    }

    try:
        # Check availability first
        availability = _check_availability(domain)
        if availability and availability.get("available"):
            result["available"] = True
            result["wayback_url"] = availability.get("url")

        # Fetch snapshots for first/last seen
        snapshots = _fetch_cdx_snapshots(domain, limit=100)
        if snapshots:
            result["available"] = True
            timestamps = [s.get("timestamp", "") for s in snapshots if s.get("timestamp")]
            if timestamps:
                timestamps_sorted = sorted(timestamps)
                result["first_seen"] = _format_timestamp(timestamps_sorted[0])
                result["last_seen"] = _format_timestamp(timestamps_sorted[-1])

            # Store sample (most recent 10)
            sample = sorted(snapshots, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
            result["snapshots_sample"] = [
                {
                    "date": _format_timestamp(s.get("timestamp", "")),
                    "url": s.get("original", ""),
                    "status": s.get("statuscode", ""),
                }
                for s in sample
            ]

        # Get total count (approximate)
        count = _fetch_total_count(domain)
        result["snapshot_count"] = count

        # Find interesting URLs
        all_urls = _fetch_all_urls_for_interesting(domain)
        interesting = [url for url in all_urls if _is_interesting_url(url)]
        # Deduplicate and limit
        seen = set()
        unique_interesting = []
        for url in interesting:
            if url not in seen:
                seen.add(url)
                unique_interesting.append(url)
                if len(unique_interesting) >= 30:
                    break
        result["interesting_urls"] = unique_interesting

    except Exception as e:
        result["error"] = str(e)

    if verbose:
        _display_archive(result)

    return result


def _display_archive(result: Dict[str, Any]) -> None:
    """Display archive analysis results with rich panel and table."""
    domain = result.get("domain", "")

    # Summary panel
    available = result.get("available", False)
    available_str = "[green]Yes[/green]" if available else "[red]No[/red]"
    first_seen = result.get("first_seen") or "Unknown"
    last_seen = result.get("last_seen") or "Unknown"
    count = result.get("snapshot_count")
    count_str = str(count) if count is not None else "Unknown"
    wayback = result.get("wayback_url") or "N/A"

    summary_lines = [
        f"[bold]Available:[/bold] {available_str}",
        f"[bold]First Seen:[/bold] {first_seen}",
        f"[bold]Last Seen:[/bold] {last_seen}",
        f"[bold]Snapshots:[/bold] ~{count_str}",
        f"[bold]Latest Snapshot:[/bold] {wayback}",
    ]

    console.print(Panel(
        "\n".join(summary_lines),
        title=f"[bold cyan]Wayback Machine Archive - {domain}[/bold cyan]",
        border_style="cyan",
    ))

    # Interesting URLs
    interesting = result.get("interesting_urls", [])
    if interesting:
        url_table = Table(
            title="[bold yellow]Interesting Archived URLs[/bold yellow]",
            show_header=True,
            header_style="bold yellow",
            border_style="yellow",
            expand=True,
        )
        url_table.add_column("#", style="dim", width=4)
        url_table.add_column("URL", style="yellow", overflow="fold")

        for i, url in enumerate(interesting[:20], 1):
            url_table.add_row(str(i), url)

        if len(interesting) > 20:
            url_table.add_row("...", f"[dim]+{len(interesting) - 20} more[/dim]")

        console.print(url_table)
    else:
        console.print("  [dim]No notably interesting archived URLs detected.[/dim]")
