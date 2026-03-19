"""
NetTrace v2 - Port Scanner Module
Uses socket.connect_ex() for TCP port scanning with optional banner grabbing.
Only runs when explicitly called with active mode enabled.
"""
import socket
import threading
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import requests.exceptions

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from config import COMMON_PORTS, PORT_SCAN_TIMEOUT, PORT_SERVICES

console = Console()


def _tcp_connect(host: str, port: int) -> bool:
    """Attempt TCP connection to host:port. Returns True if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_SCAN_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _grab_http_banner(host: str, port: int) -> Optional[str]:
    """
    Try to grab a banner from HTTP port via HEAD request.
    Returns server header or None.
    """
    scheme = "https" if port in (443, 8443) else "http"
    try:
        resp = requests.head(
            f"{scheme}://{host}:{port}",
            timeout=PORT_SCAN_TIMEOUT + 1,
            verify=False,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        server = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")
        banner_parts = []
        if server:
            banner_parts.append(f"Server: {server}")
        if powered_by:
            banner_parts.append(f"X-Powered-By: {powered_by}")
        banner_parts.append(f"HTTP {resp.status_code}")
        return " | ".join(banner_parts) if banner_parts else None
    except Exception:
        return None


def _grab_raw_banner(host: str, port: int) -> Optional[str]:
    """
    Try to grab a text banner from a raw TCP connection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_SCAN_TIMEOUT + 1)
        sock.connect((host, port))
        # Send a minimal probe for some services
        if port == 22:
            banner = sock.recv(256)
            sock.close()
            text = banner.decode("utf-8", errors="replace").strip()
            return text[:100] if text else None
        elif port == 21:
            banner = sock.recv(256)
            sock.close()
            return banner.decode("utf-8", errors="replace").strip()[:100]
        elif port == 25:
            banner = sock.recv(256)
            sock.close()
            return banner.decode("utf-8", errors="replace").strip()[:100]
        sock.close()
        return None
    except Exception:
        return None


def _scan_port(host: str, port: int) -> Dict[str, Any]:
    """Scan a single port and return result dict."""
    is_open = _tcp_connect(host, port)
    if not is_open:
        return {"port": port, "open": False}

    service_name = PORT_SERVICES.get(port, "Unknown")
    banner = None

    # Banner grabbing for known service types
    if port in (80, 443, 8080, 8443, 8888):
        banner = _grab_http_banner(host, port)
    elif port in (21, 22, 25):
        banner = _grab_raw_banner(host, port)

    return {
        "port": port,
        "open": True,
        "service": service_name,
        "banner": banner,
    }


def scan_ports(
    domain: str,
    ips: List[str],
    ports: Optional[List[int]] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Scan common ports on all IPs for the domain.

    Args:
        domain: target domain name
        ips: list of IP addresses to scan
        ports: list of ports to scan (defaults to COMMON_PORTS)
        verbose: display rich output

    Returns dict with:
      - open_ports: list of {port, service, banner, ip}
      - scanned_ips: list of IPs scanned
      - total_open: int
      - scan_summary: dict mapping port -> bool
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "open_ports": [],
        "scanned_ips": ips,
        "total_open": 0,
        "scan_summary": {},
        "error": None,
    }

    if not ips:
        result["error"] = "No IPs to scan"
        return result

    scan_ports_list = ports if ports else COMMON_PORTS
    open_ports = []

    # Scan first IP (primary) - scanning all IPs would be excessive
    primary_ip = ips[0]

    # Use thread pool for faster scanning
    max_workers = min(20, len(scan_ports_list))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(scan_ports_list)} ports on {primary_ip}...",
            total=len(scan_ports_list),
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_scan_port, primary_ip, port): port
                for port in scan_ports_list
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    port_result = future.result()
                    result["scan_summary"][port] = port_result.get("open", False)
                    if port_result.get("open"):
                        port_result["ip"] = primary_ip
                        open_ports.append(port_result)
                except Exception:
                    result["scan_summary"][port] = False
                progress.advance(task)

    # Sort open ports by port number
    open_ports.sort(key=lambda x: x["port"])
    result["open_ports"] = open_ports
    result["total_open"] = len(open_ports)

    if verbose:
        _display_ports(result)

    return result


def _display_ports(result: Dict[str, Any]) -> None:
    """Display port scan results with rich table."""
    domain = result.get("domain", "")
    open_ports = result.get("open_ports", [])

    if not open_ports:
        console.print(f"  [green]No open ports found on common ports for {domain}[/green]")
        return

    table = Table(
        title=f"[bold cyan]Port Scan Results - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Port", style="cyan", width=8)
    table.add_column("Service", style="green", width=14)
    table.add_column("IP", style="white", width=18)
    table.add_column("Banner / Info", style="dim", overflow="fold")

    for port_info in open_ports:
        port = port_info.get("port", 0)
        service = port_info.get("service", "Unknown")
        ip = port_info.get("ip", "")
        banner = port_info.get("banner") or "[dim]N/A[/dim]"

        # Color-code dangerous ports
        dangerous = port in (23, 21, 3389, 445)
        port_str = f"[red bold]{port}[/red bold]" if dangerous else f"[green]{port}[/green]"
        service_str = f"[red]{service}[/red]" if dangerous else service

        table.add_row(port_str, service_str, ip, str(banner))

    console.print(table)
    console.print(f"  [bold]Total open ports:[/bold] [cyan]{result.get('total_open', 0)}[/cyan]")
