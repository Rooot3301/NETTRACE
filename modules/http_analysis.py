"""
NetTrace v2 - HTTP/TLS Analysis Module
Fetches HTTP/HTTPS responses, extracts security headers, TLS certificate info,
technology fingerprints, and detects WAF/CDN presence.
"""
import ssl
import socket
import datetime
from typing import Dict, Any, Optional, List, Tuple

import requests
import requests.exceptions

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import DEFAULT_TIMEOUT, WAF_SIGNATURES, CDN_SIGNATURES, TAKEOVER_FINGERPRINTS

console = Console()

# Security headers to check - field name -> display name
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-XSS-Protection": "X-XSS-Protection",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
    "Cross-Origin-Embedder-Policy": "COEP",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
}

# Points per security header
HEADER_POINTS = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 25,
    "X-Frame-Options": 15,
    "X-Content-Type-Options": 15,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "X-XSS-Protection": 5,
}

# Technology fingerprints from response headers
TECH_SIGNATURES = {
    "nginx": [("Server", "nginx")],
    "Apache": [("Server", "Apache")],
    "Microsoft IIS": [("Server", "Microsoft-IIS")],
    "LiteSpeed": [("Server", "LiteSpeed")],
    "Cloudflare": [("Server", "cloudflare"), ("CF-Ray", None)],
    "WordPress": [("X-Powered-By", "WordPress"), ("Link", "wp-json")],
    "Drupal": [("X-Generator", "Drupal"), ("X-Drupal-Cache", None)],
    "Joomla": [("X-Content-Encoded-By", "Joomla")],
    "PHP": [("X-Powered-By", "PHP")],
    "ASP.NET": [("X-Powered-By", "ASP.NET"), ("X-AspNet-Version", None)],
    "Express.js": [("X-Powered-By", "Express")],
    "OpenResty": [("Server", "openresty")],
    "Varnish": [("X-Varnish", None), ("Via", "varnish")],
    "Squarespace": [("Server", "Squarespace")],
    "Shopify": [("X-ShopId", None), ("X-Shopify-Stage", None)],
    "AWS S3": [("Server", "AmazonS3"), ("x-amz-request-id", None)],
    "Google Frontend": [("Server", "Google Frontend"), ("Via", "Google")],
}


def _get_tls_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieve TLS certificate details for a host.
    Returns dict with issuer, subject, SAN, expiry, days_until_expiry, tls_version.
    """
    result: Dict[str, Any] = {
        "issuer": "",
        "subject": "",
        "san": [],
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,
        "tls_version": "",
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["tls_version"] = ssock.version() or ""
                cert = ssock.getpeercert()
                if cert:
                    # Subject
                    subject_dict = {}
                    for item in cert.get("subject", []):
                        for k, v in item:
                            subject_dict[k] = v
                    result["subject"] = subject_dict.get("commonName", "")

                    # Issuer
                    issuer_dict = {}
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            issuer_dict[k] = v
                    org = issuer_dict.get("organizationName", "")
                    cn = issuer_dict.get("commonName", "")
                    result["issuer"] = org or cn

                    # SAN
                    san_list = []
                    for san_type, san_val in cert.get("subjectAltName", []):
                        if san_type.lower() == "dns":
                            san_list.append(san_val)
                    result["san"] = san_list

                    # Expiry
                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")
                    result["not_after"] = not_after_str
                    result["not_before"] = not_before_str
                    if not_after_str:
                        try:
                            expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
                            now = datetime.datetime.now(datetime.timezone.utc)
                            result["days_until_expiry"] = (expiry - now).days
                        except ValueError:
                            pass
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def _detect_technologies(headers: Dict[str, str], body: str = "") -> List[str]:
    """Detect technologies from response headers."""
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for tech, signatures in TECH_SIGNATURES.items():
        for header_name, header_value in signatures:
            h_lower = header_name.lower()
            if h_lower in headers_lower:
                if header_value is None:
                    detected.append(tech)
                    break
                elif header_value.lower() in headers_lower[h_lower]:
                    detected.append(tech)
                    break

    return list(dict.fromkeys(detected))  # deduplicate preserving order


def _detect_waf(headers: Dict[str, str], body: str = "") -> Optional[str]:
    """Detect WAF from response headers."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()[:5000] if body else ""

    for header_pat, waf_name in WAF_SIGNATURES.items():
        h_lower = header_pat.lower()
        # Check as header name
        if h_lower in headers_lower:
            return waf_name
        # Check as header value pattern
        for hv in headers_lower.values():
            if h_lower in hv:
                return waf_name

    return None


def _detect_cdn(headers: Dict[str, str]) -> Optional[str]:
    """Detect CDN from response headers."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    server_val = headers_lower.get("server", "")
    via_val = headers_lower.get("via", "")
    combined = server_val + " " + via_val

    for cdn_name, patterns in CDN_SIGNATURES.items():
        for pattern in patterns:
            if pattern.lower() in combined:
                return cdn_name
    return None


def _calculate_headers_score(present_headers: List[str]) -> int:
    """Calculate security headers score 0-100."""
    total_points = sum(HEADER_POINTS.values())  # 100 max
    earned = sum(HEADER_POINTS.get(h, 0) for h in present_headers)
    return min(100, int((earned / total_points) * 100))


def _fetch_url(url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
    """Fetch URL and return (response, error_str)."""
    try:
        resp = requests.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetTrace/2.0)"},
        )
        return resp, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {str(e)[:100]}"
    except requests.exceptions.Timeout:
        return None, "Connection timeout"
    except Exception as e:
        return None, str(e)[:100]


def analyze_http(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Perform HTTP/TLS analysis for a domain.

    Returns dict with:
      - http_status, https_status, redirect_to_https
      - security_headers: dict of header name -> value
      - missing_headers: list of security headers not present
      - headers_score: 0-100
      - tls_info: dict
      - technologies: list
      - waf: detected WAF name or None
      - cdn: detected CDN from headers or None
      - server: Server header value
      - x_powered_by: X-Powered-By value
      - final_url: URL after redirects
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "http_status": None,
        "https_status": None,
        "http_reachable": False,
        "https_reachable": False,
        "redirect_to_https": False,
        "final_url": "",
        "security_headers": {},
        "missing_headers": [],
        "headers_score": 0,
        "tls_info": {},
        "technologies": [],
        "waf": None,
        "cdn": None,
        "server": "",
        "x_powered_by": "",
        "all_response_headers": {},
        "error": None,
    }

    # Suppress InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Try HTTPS first
    https_resp, https_err = _fetch_url(f"https://{domain}")
    if https_resp is not None:
        result["https_reachable"] = True
        result["https_status"] = https_resp.status_code
        result["final_url"] = https_resp.url
        all_headers = dict(https_resp.headers)
        result["all_response_headers"] = all_headers

        # Extract security headers
        found_headers = {}
        missing_headers = []
        for header in SECURITY_HEADERS:
            val = https_resp.headers.get(header)
            if val:
                found_headers[header] = val
            else:
                missing_headers.append(header)

        result["security_headers"] = found_headers
        result["missing_headers"] = missing_headers
        result["headers_score"] = _calculate_headers_score(list(found_headers.keys()))

        # Server and powered-by
        result["server"] = https_resp.headers.get("Server", "")
        result["x_powered_by"] = https_resp.headers.get("X-Powered-By", "")

        # Technology detection
        result["technologies"] = _detect_technologies(all_headers, https_resp.text[:10000])

        # WAF detection
        result["waf"] = _detect_waf(all_headers, https_resp.text[:5000])

        # CDN detection from headers
        result["cdn"] = _detect_cdn(all_headers)

        # TLS info
        result["tls_info"] = _get_tls_info(domain)

    else:
        result["tls_info"] = {"error": https_err}

    # Try HTTP
    http_resp, http_err = _fetch_url(f"http://{domain}")
    if http_resp is not None:
        result["http_reachable"] = True
        result["http_status"] = http_resp.status_code
        # Check redirect to HTTPS
        if https_resp is None:
            all_headers = dict(http_resp.headers)
            result["all_response_headers"] = all_headers
            result["server"] = http_resp.headers.get("Server", "")
            result["x_powered_by"] = http_resp.headers.get("X-Powered-By", "")
            result["technologies"] = _detect_technologies(all_headers, http_resp.text[:10000])
            result["waf"] = _detect_waf(all_headers, http_resp.text[:5000])
            result["cdn"] = _detect_cdn(all_headers)

        # Check if HTTP redirected to HTTPS
        for r in http_resp.history:
            loc = r.headers.get("Location", "")
            if loc.startswith("https://"):
                result["redirect_to_https"] = True
                break
        if result["final_url"] and result["final_url"].startswith("https://"):
            result["redirect_to_https"] = True

    if verbose:
        _display_http(result)

    return result


def _display_http(result: Dict[str, Any]) -> None:
    """Display HTTP analysis results with rich tables."""
    domain = result.get("domain", "")

    # Connectivity summary
    table = Table(
        title=f"[bold cyan]HTTP/TLS Analysis - {domain}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Property", style="cyan", width=28)
    table.add_column("Value", style="white")

    http_status = result.get("http_status")
    https_status = result.get("https_status")
    http_str = str(http_status) if http_status else "[red]Unreachable[/red]"
    https_str = str(https_status) if https_status else "[red]Unreachable[/red]"

    redirect = "[green]Yes[/green]" if result.get("redirect_to_https") else "[yellow]No[/yellow]"

    table.add_row("HTTP Status", http_str)
    table.add_row("HTTPS Status", https_str)
    table.add_row("HTTP -> HTTPS Redirect", redirect)
    table.add_row("Final URL", result.get("final_url", ""))
    table.add_row("Server", result.get("server") or "[dim]N/A[/dim]")
    table.add_row("X-Powered-By", result.get("x_powered_by") or "[dim]N/A[/dim]")
    table.add_row("WAF Detected", result.get("waf") or "[dim]None detected[/dim]")
    table.add_row("CDN (headers)", result.get("cdn") or "[dim]None detected[/dim]")
    table.add_row("Technologies", ", ".join(result.get("technologies", [])) or "[dim]None detected[/dim]")
    table.add_row("Security Score", f"{result.get('headers_score', 0)}/100")

    console.print(table)

    # Security headers table
    sec_table = Table(
        title="[bold cyan]Security Headers[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    sec_table.add_column("Header", style="cyan", width=35)
    sec_table.add_column("Status", style="white", width=10)
    sec_table.add_column("Value", style="dim", overflow="fold")

    sec_headers = result.get("security_headers", {})
    missing = result.get("missing_headers", [])

    for header in SECURITY_HEADERS:
        if header in sec_headers:
            val = sec_headers[header]
            short_val = val[:80] + "..." if len(val) > 80 else val
            sec_table.add_row(header, "[green]Present[/green]", short_val)
        else:
            sec_table.add_row(header, "[red]Missing[/red]", "")

    console.print(sec_table)

    # TLS info
    tls = result.get("tls_info", {})
    if tls and not tls.get("error"):
        tls_table = Table(
            title="[bold cyan]TLS Certificate[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
        )
        tls_table.add_column("Field", style="cyan", width=22)
        tls_table.add_column("Value", style="white")

        days = tls.get("days_until_expiry")
        if days is not None:
            if days < 0:
                days_str = f"[red bold]EXPIRED {abs(days)} days ago[/red bold]"
            elif days < 30:
                days_str = f"[red]{days} days (EXPIRING SOON)[/red]"
            elif days < 90:
                days_str = f"[yellow]{days} days[/yellow]"
            else:
                days_str = f"[green]{days} days[/green]"
        else:
            days_str = "[dim]N/A[/dim]"

        san_list = tls.get("san", [])
        san_str = ", ".join(san_list[:5])
        if len(san_list) > 5:
            san_str += f" (+{len(san_list)-5} more)"

        tls_table.add_row("TLS Version", tls.get("tls_version", "") or "[dim]N/A[/dim]")
        tls_table.add_row("Subject (CN)", tls.get("subject", "") or "[dim]N/A[/dim]")
        tls_table.add_row("Issuer", tls.get("issuer", "") or "[dim]N/A[/dim]")
        tls_table.add_row("Valid Until", tls.get("not_after", "") or "[dim]N/A[/dim]")
        tls_table.add_row("Days Until Expiry", days_str)
        tls_table.add_row("SAN", san_str or "[dim]N/A[/dim]")

        console.print(tls_table)
