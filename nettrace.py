#!/usr/bin/env python3
"""
NetTrace v2 - Advanced OSINT Domain Analysis Tool
A comprehensive domain intelligence and security analysis tool.
Requires no paid API keys - uses only free public services.
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import print as rprint
from rich.columns import Columns
from rich.rule import Rule

from config import VERSION, TOOL_NAME, AUTHOR
from cache import CacheManager

console = Console()

BANNER = r"""
  _   _      _   _____
 | \ | | ___| |_|_   _| __ __ _  ___ ___
 |  \| |/ _ \ __| | || '__/ _` |/ __/ _ \
 | |\  |  __/ |_  | || | | (_| | (_|  __/
 |_| \_|\___|\__| |_||_|  \__,_|\___\___|
"""

# Valid domain pattern
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def print_banner() -> None:
    """Print the NetTrace banner using rich."""
    banner_text = Text(BANNER)
    banner_text.stylize("bold cyan")
    console.print(banner_text)
    console.print(
        Panel(
            f"[bold white]{TOOL_NAME} v{VERSION}[/bold white]  "
            f"[dim]Advanced OSINT Domain Analysis[/dim]  "
            f"[dim]No API keys required[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def validate_domain(domain: str) -> bool:
    """Return True if domain is a valid-looking domain name."""
    domain = domain.strip().lower()
    # Strip http/https prefix if user pasted a URL
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Strip trailing slash
    domain = domain.rstrip("/").split("/")[0].split("?")[0]
    if not domain or "." not in domain:
        return False
    return bool(DOMAIN_RE.match(domain))


def clean_domain(domain: str) -> str:
    """Clean and normalize a domain string."""
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/").split("/")[0].split("?")[0]
    return domain


def run_analysis(domain: str, options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Run full domain analysis pipeline.

    Args:
        domain: validated domain name
        options: dict with keys: verbose, active, no_cache, json_only

    Returns:
        Complete results dict, or None on fatal error.
    """
    verbose = options.get("verbose", False)
    active = options.get("active", False)
    no_cache = options.get("no_cache", False)
    json_only = options.get("json_only", False)

    domain = clean_domain(domain)

    if not validate_domain(domain):
        if not json_only:
            console.print(f"[red]Invalid domain: {domain}[/red]")
        return None

    cache = CacheManager()

    # Check cache first
    if not no_cache:
        cached = cache.get(domain)
        if cached:
            if not json_only:
                console.print(f"[dim]Using cached results for [cyan]{domain}[/cyan] (use --no-cache to refresh)[/dim]")
            return cached

    # Deferred imports to keep startup fast
    from modules.dns_analysis import analyze_dns
    from modules.whois_analysis import analyze_whois
    from modules.http_analysis import analyze_http
    from modules.geo_analysis import analyze_geo
    from modules.subdomain_analysis import analyze_subdomains
    from modules.email_security import analyze_email_security
    from modules.archive import analyze_archive
    from modules.port_scanner import scan_ports
    from modules.scoring import calculate_risk_score
    from modules.dorks import generate_dorks

    results: Dict[str, Any] = {
        "domain": domain,
        "analysis_date": datetime.utcnow().isoformat(),
        "whois": {},
        "dns": {},
        "http": {},
        "geo": {},
        "subdomains": {},
        "email": {},
        "archive": {},
        "ports": None,
        "scoring": {},
        "dorks": {},
    }

    total_steps = 9 if not active else 10
    # Active scan adds port scanning

    if not json_only:
        console.print(f"\n[bold cyan]Analyzing:[/bold cyan] [white]{domain}[/white]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=not json_only,
        disable=json_only,
    ) as progress:
        task = progress.add_task("[cyan]Starting analysis...", total=total_steps)

        # Step 1: WHOIS
        progress.update(task, description="[cyan]Step 1/9  WHOIS lookup...", advance=0)
        try:
            results["whois"] = analyze_whois(domain, verbose=False)
        except Exception as e:
            results["whois"] = {"error": str(e)}
        progress.advance(task)

        # Step 2: DNS
        progress.update(task, description="[cyan]Step 2/9  DNS analysis...")
        try:
            results["dns"] = analyze_dns(domain, verbose=False)
        except Exception as e:
            results["dns"] = {"error": str(e)}
        progress.advance(task)

        # Step 3: HTTP/TLS
        progress.update(task, description="[cyan]Step 3/9  HTTP/TLS fingerprinting...")
        try:
            results["http"] = analyze_http(domain, verbose=False)
        except Exception as e:
            results["http"] = {"error": str(e)}
        progress.advance(task)

        # Step 4: GeoIP
        progress.update(task, description="[cyan]Step 4/9  GeoIP lookup...")
        try:
            ips = results["dns"].get("ips", []) if results["dns"] else []
            if ips:
                results["geo"] = analyze_geo(domain, ips, verbose=False)
            else:
                results["geo"] = {"domain": domain, "error": "No IPs found", "ip_info": [],
                                  "unique_countries": [], "unique_asns": [], "is_behind_cdn": False}
        except Exception as e:
            results["geo"] = {"error": str(e)}
        progress.advance(task)

        # Step 5: Subdomains
        progress.update(task, description="[cyan]Step 5/9  Subdomain enumeration...")
        try:
            results["subdomains"] = analyze_subdomains(domain, verbose=False)
        except Exception as e:
            results["subdomains"] = {"error": str(e), "subdomains": [], "total_count": 0}
        progress.advance(task)

        # Step 6: Email Security
        progress.update(task, description="[cyan]Step 6/9  Email security checks...")
        try:
            results["email"] = analyze_email_security(domain, results.get("dns", {}), verbose=False)
        except Exception as e:
            results["email"] = {"error": str(e)}
        progress.advance(task)

        # Step 7: Archive
        progress.update(task, description="[cyan]Step 7/9  Wayback Machine archive...")
        try:
            results["archive"] = analyze_archive(domain, verbose=False)
        except Exception as e:
            results["archive"] = {"error": str(e)}
        progress.advance(task)

        # Step 8: Port scan (optional)
        if active:
            progress.update(task, description="[cyan]Step 8/9  Port scanning (active)...")
            try:
                ips = results["dns"].get("ips", []) if results["dns"] else []
                results["ports"] = scan_ports(domain, ips, verbose=False)
            except Exception as e:
                results["ports"] = {"error": str(e), "open_ports": []}
            progress.advance(task)

        # Step 9: Risk Scoring
        progress.update(task, description="[cyan]Step 9/9  Calculating risk score...")
        try:
            results["scoring"] = calculate_risk_score(
                results.get("whois"),
                results.get("dns"),
                results.get("http"),
                results.get("geo"),
                results.get("subdomains"),
                results.get("email"),
                results.get("archive"),
                results.get("ports"),
            )
        except Exception as e:
            results["scoring"] = {"error": str(e), "score": 0, "risk_level": "HIGH_RISK"}
        progress.advance(task)

        # Dorks (instant, no network)
        try:
            results["dorks"] = generate_dorks(domain)
        except Exception:
            results["dorks"] = {}

        progress.update(task, description="[green]Analysis complete!")

    # Cache the results
    if not no_cache:
        cache.set(domain, results)

    return results


def display_results(results: Dict[str, Any]) -> None:
    """Display complete analysis results using rich tables and panels."""
    if not results:
        console.print("[red]No results to display.[/red]")
        return

    domain = results.get("domain", "unknown")
    analysis_date = results.get("analysis_date", "")

    console.print()
    console.print(Rule(f"[bold cyan] Results for {domain} [/bold cyan]", style="cyan"))
    console.print()

    # ---- Summary Panel ----
    scoring = results.get("scoring", {})
    score = scoring.get("score", 0)
    risk_level = scoring.get("risk_level", "HIGH_RISK")
    risk_label = scoring.get("risk_label", "Unknown")

    risk_colors = {
        "LOW_RISK": "green",
        "MEDIUM_RISK": "yellow",
        "ELEVATED_RISK": "dark_orange",
        "HIGH_RISK": "red",
    }
    rc = risk_colors.get(risk_level, "white")

    bar_width = 30
    filled = int((score / 100) * bar_width)
    bar = "[" + "█" * filled + "░" * (bar_width - filled) + "]"

    summary_content = (
        f"[bold white]Domain:[/bold white] [cyan]{domain}[/cyan]\n"
        f"[bold white]Date:[/bold white]   [dim]{analysis_date}[/dim]\n"
        f"[bold white]Score:[/bold white]  [{rc} bold]{score}/100[/{rc} bold]  [{rc}]{risk_label}[/{rc}]\n"
        f"        [{rc}]{bar}[/{rc}]"
    )

    console.print(Panel(summary_content, title="[bold cyan]Analysis Summary[/bold cyan]", border_style="cyan"))

    # ---- WHOIS ----
    console.print(Rule("[bold cyan]WHOIS[/bold cyan]", style="cyan"))
    from modules.whois_analysis import _display_whois
    _display_whois(results.get("whois", {}))

    # ---- DNS ----
    console.print(Rule("[bold cyan]DNS[/bold cyan]", style="cyan"))
    from modules.dns_analysis import _display_dns
    _display_dns(results.get("dns", {}))

    # ---- HTTP/TLS ----
    console.print(Rule("[bold cyan]HTTP / TLS[/bold cyan]", style="cyan"))
    from modules.http_analysis import _display_http
    _display_http(results.get("http", {}))

    # ---- GeoIP ----
    console.print(Rule("[bold cyan]GeoIP[/bold cyan]", style="cyan"))
    from modules.geo_analysis import _display_geo
    _display_geo(results.get("geo", {}))

    # ---- Subdomains ----
    console.print(Rule("[bold cyan]Subdomains[/bold cyan]", style="cyan"))
    from modules.subdomain_analysis import _display_subdomains
    _display_subdomains(results.get("subdomains", {}))

    # ---- Email Security ----
    console.print(Rule("[bold cyan]Email Security[/bold cyan]", style="cyan"))
    from modules.email_security import _display_email_security
    _display_email_security(results.get("email", {}))

    # ---- Archive ----
    console.print(Rule("[bold cyan]Wayback Machine[/bold cyan]", style="cyan"))
    from modules.archive import _display_archive
    _display_archive(results.get("archive", {}))

    # ---- Ports (if active) ----
    ports = results.get("ports")
    if ports:
        console.print(Rule("[bold cyan]Port Scan[/bold cyan]", style="cyan"))
        from modules.port_scanner import _display_ports
        _display_ports(ports)

    # ---- Risk Score ----
    console.print(Rule("[bold cyan]Risk Assessment[/bold cyan]", style="cyan"))
    from modules.scoring import display_score
    display_score(scoring, domain)

    # ---- Dorks ----
    console.print(Rule("[bold cyan]Google Dorks[/bold cyan]", style="cyan"))
    from modules.dorks import display_dorks
    display_dorks(results.get("dorks", {}))

    # ---- VirusTotal link ----
    vt_url = f"https://www.virustotal.com/gui/domain/{domain}/detection"
    console.print()
    console.print(Panel(
        f"[dim]External check:[/dim] [link={vt_url}][cyan]{vt_url}[/cyan][/link]",
        title="[bold yellow]VirusTotal[/bold yellow]",
        border_style="yellow",
    ))
    console.print()


def compare_domains(domain1: str, domain2: str, options: Dict[str, Any]) -> None:
    """Run analysis on two domains and display side-by-side comparison."""
    console.print(f"\n[bold cyan]Comparing:[/bold cyan] [white]{domain1}[/white] vs [white]{domain2}[/white]\n")

    results1 = run_analysis(domain1, options)
    results2 = run_analysis(domain2, options)

    if not results1 or not results2:
        console.print("[red]Could not analyze one or both domains.[/red]")
        return

    table = Table(
        title=f"[bold cyan]Domain Comparison: {domain1} vs {domain2}[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Metric", style="cyan", width=28)
    table.add_column(domain1, style="white", width=30)
    table.add_column(domain2, style="white", width=30)

    def v(results, *keys):
        """Extract nested value from results dict."""
        val = results
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return "N/A"
        if val is None:
            return "N/A"
        return str(val)

    def risk_str(results):
        s = results.get("scoring", {})
        score = s.get("score", 0)
        label = s.get("risk_label", "N/A")
        return f"{score}/100 ({label})"

    def date_str(iso):
        if not iso or iso == "N/A":
            return "N/A"
        try:
            return datetime.fromisoformat(str(iso)).strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return str(iso)[:10]

    rows = [
        ("Risk Score", risk_str(results1), risk_str(results2)),
        ("Registrar", v(results1, "whois", "registrar"), v(results2, "whois", "registrar")),
        ("Created", date_str(v(results1, "whois", "creation_date")), date_str(v(results2, "whois", "creation_date"))),
        ("Domain Age (days)", v(results1, "whois", "age_days"), v(results2, "whois", "age_days")),
        ("IPs", str(len(results1.get("dns", {}).get("a_records", []))), str(len(results2.get("dns", {}).get("a_records", [])))),
        ("DNSSEC", "Yes" if results1.get("dns", {}).get("dnssec_enabled") else "No", "Yes" if results2.get("dns", {}).get("dnssec_enabled") else "No"),
        ("HTTPS", "Yes" if results1.get("http", {}).get("https_reachable") else "No", "Yes" if results2.get("http", {}).get("https_reachable") else "No"),
        ("Sec Headers Score", v(results1, "http", "headers_score") + "/100", v(results2, "http", "headers_score") + "/100"),
        ("WAF", v(results1, "http", "waf") or "None", v(results2, "http", "waf") or "None"),
        ("CDN", v(results1, "geo", "detected_cdn") or "None", v(results2, "geo", "detected_cdn") or "None"),
        ("Subdomains", v(results1, "subdomains", "total_count"), v(results2, "subdomains", "total_count")),
        ("SPF Policy", v(results1, "email", "spf", "policy") or "missing", v(results2, "email", "spf", "policy") or "missing"),
        ("DMARC Policy", v(results1, "email", "dmarc", "policy") or "missing", v(results2, "email", "dmarc", "policy") or "missing"),
        ("DKIM", "Yes" if results1.get("email", {}).get("dkim", {}).get("found") else "No", "Yes" if results2.get("email", {}).get("dkim", {}).get("found") else "No"),
        ("Email Score", v(results1, "email", "email_score") + "/100", v(results2, "email", "email_score") + "/100"),
        ("Archive First Seen", v(results1, "archive", "first_seen") or "N/A", v(results2, "archive", "first_seen") or "N/A"),
        ("Countries", ", ".join(results1.get("geo", {}).get("unique_countries", [])) or "N/A",
         ", ".join(results2.get("geo", {}).get("unique_countries", [])) or "N/A"),
        ("Takeover Candidates", str(len(results1.get("subdomains", {}).get("takeover_candidates", []))),
         str(len(results2.get("subdomains", {}).get("takeover_candidates", [])))),
    ]

    for metric, val1, val2 in rows:
        table.add_row(metric, val1, val2)

    console.print(table)


def export_results(results: Dict[str, Any], output: str, fmt: str) -> bool:
    """Export results to file in the specified format."""
    try:
        if fmt == "json":
            from exporters.json_exporter import export_json
            success = export_json(results, output)
        elif fmt == "txt":
            from exporters.txt_exporter import export_txt
            success = export_txt(results, output)
        elif fmt == "csv":
            from exporters.csv_exporter import export_csv
            success = export_csv(results, output)
        elif fmt == "html":
            from exporters.html_exporter import export_html
            success = export_html(results, output)
        else:
            console.print(f"[red]Unknown format: {fmt}[/red]")
            return False

        if success:
            console.print(f"[green]Report saved:[/green] [cyan]{output}[/cyan]")
        else:
            console.print(f"[red]Failed to save report to {output}[/red]")
        return success
    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        return False


def batch_analysis(domains: List[str], options: Dict[str, Any], output_dir: str = ".") -> None:
    """Run analysis on multiple domains and display a summary table."""
    if not domains:
        console.print("[yellow]No domains to analyze.[/yellow]")
        return

    console.print(f"\n[bold cyan]Batch Analysis:[/bold cyan] {len(domains)} domains\n")
    all_results = []

    for i, domain in enumerate(domains, 1):
        console.print(f"[cyan][{i}/{len(domains)}][/cyan] Analyzing [white]{domain}[/white]...")
        result = run_analysis(domain.strip(), options)
        if result:
            all_results.append(result)

    if not all_results:
        console.print("[red]No results obtained.[/red]")
        return

    # Summary table
    summary_table = Table(
        title=f"[bold cyan]Batch Analysis Summary ({len(all_results)} domains)[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    summary_table.add_column("Domain", style="cyan")
    summary_table.add_column("Score", width=8, justify="center")
    summary_table.add_column("Risk", width=16)
    summary_table.add_column("HTTPS", width=7, justify="center")
    summary_table.add_column("DMARC", width=12)
    summary_table.add_column("Subdomains", width=11, justify="right")
    summary_table.add_column("Age (days)", width=10, justify="right")

    risk_colors = {
        "LOW_RISK": "green",
        "MEDIUM_RISK": "yellow",
        "ELEVATED_RISK": "dark_orange",
        "HIGH_RISK": "red",
    }

    for r in all_results:
        s = r.get("scoring", {})
        score = s.get("score", 0)
        risk = s.get("risk_level", "HIGH_RISK")
        label = s.get("risk_label", "N/A")
        rc = risk_colors.get(risk, "white")

        https_ok = r.get("http", {}).get("https_reachable", False)
        https_str = "[green]Yes[/green]" if https_ok else "[red]No[/red]"

        dmarc = r.get("email", {}).get("dmarc", {})
        dmarc_str = dmarc.get("policy", "missing") if dmarc.get("found") else "[red]missing[/red]"

        sub_count = r.get("subdomains", {}).get("total_count", 0)
        age = r.get("whois", {}).get("age_days", "N/A")

        summary_table.add_row(
            r.get("domain", ""),
            f"[{rc} bold]{score}[/{rc} bold]",
            f"[{rc}]{label}[/{rc}]",
            https_str,
            str(dmarc_str),
            str(sub_count),
            str(age),
        )

    console.print(summary_table)


def system_check() -> None:
    """Check availability of optional external tools and Python dependencies."""
    import shutil
    import importlib

    console.print(Panel("[bold cyan]System Check[/bold cyan]", border_style="cyan"))

    table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
    table.add_column("Component", style="cyan", width=30)
    table.add_column("Status", width=14)
    table.add_column("Version / Notes", style="dim")

    # Python packages
    packages = [
        ("requests", "requests"),
        ("dnspython", "dns"),
        ("python-whois", "whois"),
        ("rich", "rich"),
        ("python-dateutil", "dateutil"),
    ]

    for pkg_name, import_name in packages:
        try:
            mod = importlib.import_module(import_name)
            version = getattr(mod, "__version__", "installed")
            table.add_row(f"Python: {pkg_name}", "[green]OK[/green]", version)
        except ImportError:
            table.add_row(f"Python: {pkg_name}", "[red]MISSING[/red]", f"pip install {pkg_name}")

    # External tools
    for tool in ["subfinder", "amass", "nmap"]:
        if shutil.which(tool):
            table.add_row(f"Tool: {tool}", "[green]Available[/green]", shutil.which(tool))
        else:
            table.add_row(f"Tool: {tool}", "[dim]Not installed[/dim]", "Optional")

    # Cache check
    cache = CacheManager()
    cached = cache.list_cached()
    table.add_row("Cache directory", "[green]OK[/green]", str(cache.cache_dir))
    table.add_row("Cached domains", "[cyan]Info[/cyan]", str(len(cached)))

    console.print(table)


def show_interactive_menu() -> None:
    """Display interactive menu with rich prompts."""
    print_banner()

    options: Dict[str, Any] = {
        "verbose": False,
        "active": False,
        "no_cache": False,
        "json_only": False,
    }

    while True:
        console.print()
        console.print(Panel(
            "[bold cyan]1.[/bold cyan] Single domain analysis\n"
            "[bold cyan]2.[/bold cyan] Report generation (choose format)\n"
            "[bold cyan]3.[/bold cyan] Batch analysis\n"
            "[bold cyan]4.[/bold cyan] Compare two domains\n"
            "[bold cyan]5.[/bold cyan] System check\n"
            "[bold cyan]6.[/bold cyan] Clear cache\n"
            "[bold cyan]7.[/bold cyan] Help\n"
            "[bold cyan]8.[/bold cyan] Exit",
            title="[bold white]NetTrace v2 - Main Menu[/bold white]",
            border_style="cyan",
        ))

        try:
            choice = Prompt.ask(
                "[bold cyan]Select option[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                default="1",
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Use option 8 to exit.[/yellow]")
            continue

        if choice == "1":
            # Single domain analysis
            try:
                domain = Prompt.ask("[cyan]Enter domain[/cyan] (e.g. example.com)")
                domain = clean_domain(domain)
                if not validate_domain(domain):
                    console.print("[red]Invalid domain. Please enter a valid domain like example.com[/red]")
                    continue
                options["verbose"] = True
                results = run_analysis(domain, options)
                if results:
                    display_results(results)
                    if Confirm.ask("[cyan]Save report?[/cyan]", default=False):
                        fmt = Prompt.ask(
                            "[cyan]Format[/cyan]",
                            choices=["json", "txt", "html", "csv"],
                            default="html",
                        )
                        default_name = f"{domain}_report.{fmt}"
                        filename = Prompt.ask("[cyan]Filename[/cyan]", default=default_name)
                        export_results(results, filename, fmt)
            except KeyboardInterrupt:
                console.print("\n[yellow]Analysis interrupted.[/yellow]")

        elif choice == "2":
            # Report generation from last result or new domain
            try:
                domain = Prompt.ask("[cyan]Enter domain[/cyan]")
                domain = clean_domain(domain)
                if not validate_domain(domain):
                    console.print("[red]Invalid domain.[/red]")
                    continue
                fmt = Prompt.ask(
                    "[cyan]Report format[/cyan]",
                    choices=["json", "txt", "html", "csv"],
                    default="html",
                )
                default_name = f"{domain}_report.{fmt}"
                filename = Prompt.ask("[cyan]Output filename[/cyan]", default=default_name)
                results = run_analysis(domain, options)
                if results:
                    export_results(results, filename, fmt)
                    console.print(f"[green]Report saved:[/green] {filename}")
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted.[/yellow]")

        elif choice == "3":
            # Batch analysis
            try:
                console.print("[dim]Enter domains one per line. Empty line to finish, or enter a filename.[/dim]")
                source = Prompt.ask(
                    "[cyan]Enter domains or filename[/cyan]",
                    default="",
                )
                domains = []
                if source and "." in source and not validate_domain(source):
                    # Treat as filename
                    try:
                        with open(source, "r") as f:
                            domains = [line.strip() for line in f if line.strip()]
                    except OSError as e:
                        console.print(f"[red]Could not read file: {e}[/red]")
                        continue
                else:
                    if source:
                        domains = [source]
                    # Read more domains
                    while True:
                        extra = Prompt.ask("[cyan]Add domain (empty to start)[/cyan]", default="")
                        if not extra:
                            break
                        domains.append(extra.strip())

                if domains:
                    batch_analysis(domains, options)
                else:
                    console.print("[yellow]No domains entered.[/yellow]")
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted.[/yellow]")

        elif choice == "4":
            # Compare two domains
            try:
                d1 = Prompt.ask("[cyan]Enter first domain[/cyan]")
                d2 = Prompt.ask("[cyan]Enter second domain[/cyan]")
                d1 = clean_domain(d1)
                d2 = clean_domain(d2)
                if not validate_domain(d1) or not validate_domain(d2):
                    console.print("[red]One or both domains are invalid.[/red]")
                    continue
                compare_domains(d1, d2, options)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted.[/yellow]")

        elif choice == "5":
            system_check()

        elif choice == "6":
            # Clear cache
            cache = CacheManager()
            cached_list = cache.list_cached()
            if not cached_list:
                console.print("[dim]Cache is already empty.[/dim]")
                continue
            console.print(f"[dim]Found {len(cached_list)} cached domain(s).[/dim]")
            try:
                if Confirm.ask("[yellow]Clear all cache?[/yellow]", default=False):
                    cleared = cache.clear()
                    console.print(f"[green]Cleared {cleared} cache file(s).[/green]")
                else:
                    specific = Prompt.ask("[cyan]Clear specific domain (or empty to cancel)[/cyan]", default="")
                    if specific:
                        cleared = cache.clear(clean_domain(specific))
                        console.print(f"[green]Cleared {cleared} cache file(s).[/green]")
            except KeyboardInterrupt:
                pass

        elif choice == "7":
            console.print(Panel(
                "[bold white]NetTrace v2 - Help[/bold white]\n\n"
                "[cyan]Purpose:[/cyan] OSINT domain intelligence and security analysis tool.\n\n"
                "[cyan]Modules:[/cyan]\n"
                "  • WHOIS - Registrar, age, expiry, privacy check\n"
                "  • DNS   - A/AAAA/MX/TXT/NS, DNSSEC, zone transfer test\n"
                "  • HTTP  - TLS cert, security headers, WAF/CDN detection\n"
                "  • GeoIP - IP geolocation via ip-api.com\n"
                "  • Subs  - crt.sh CT logs, subfinder/amass (if installed)\n"
                "  • Email - SPF, DMARC, DKIM, BIMI, MTA-STS\n"
                "  • Archive - Wayback Machine CDX API\n"
                "  • Ports - TCP port scan (active mode only)\n"
                "  • Score - Unified risk scoring 0-100\n"
                "  • Dorks - Pre-built Google OSINT queries\n\n"
                "[cyan]CLI Usage:[/cyan]\n"
                "  python nettrace.py -d example.com\n"
                "  python nettrace.py -d example.com -o report.html -f html\n"
                "  python nettrace.py -d example.com --active\n"
                "  python nettrace.py --compare domain1.com domain2.com\n"
                "  python nettrace.py --json -d example.com\n",
                border_style="cyan",
            ))

        elif choice == "8":
            console.print("[bold cyan]Goodbye![/bold cyan]")
            sys.exit(0)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} - Advanced OSINT Domain Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nettrace.py --domain google.com
  python nettrace.py -d example.com -o report.html -f html
  python nettrace.py -d example.com --active
  python nettrace.py --compare domain1.com domain2.com
  python nettrace.py --json -d example.com
  python nettrace.py --interactive
  python nettrace.py --clear-cache
        """,
    )

    parser.add_argument(
        "--domain", "-d",
        metavar="DOMAIN",
        help="Domain to analyze (e.g. google.com)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Output filename for report",
    )
    parser.add_argument(
        "--format", "-f",
        dest="fmt",
        choices=["json", "txt", "html", "csv"],
        default="json",
        help="Report format: json, txt, html, csv (default: json)",
    )
    parser.add_argument(
        "--active", "-a",
        action="store_true",
        help="Enable active port scanning (opt-in, sends packets to target)",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("DOMAIN1", "DOMAIN2"),
        help="Compare two domains side by side",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass local cache and force fresh analysis",
    )
    parser.add_argument(
        "--json",
        dest="json_only",
        action="store_true",
        help="Output raw JSON only (no rich formatting, suitable for piping)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose mode - show detailed output during analysis",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive menu mode",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the local analysis cache and exit",
    )

    args = parser.parse_args()

    # Handle --clear-cache
    if args.clear_cache:
        cache = CacheManager()
        count = cache.clear()
        console.print(f"[green]Cache cleared: {count} file(s) removed.[/green]")
        sys.exit(0)

    # Handle --compare
    if args.compare:
        d1, d2 = args.compare
        d1 = clean_domain(d1)
        d2 = clean_domain(d2)
        if not validate_domain(d1) or not validate_domain(d2):
            console.print("[red]One or both domains are invalid.[/red]")
            sys.exit(1)
        if not args.json_only:
            print_banner()
        options = {
            "verbose": args.verbose,
            "active": args.active,
            "no_cache": args.no_cache,
            "json_only": args.json_only,
        }
        compare_domains(d1, d2, options)
        sys.exit(0)

    # Interactive mode (default if no domain given)
    if args.interactive or not args.domain:
        show_interactive_menu()
        sys.exit(0)

    # Single domain analysis
    if not args.json_only:
        print_banner()

    if args.active and not args.json_only:
        console.print(Panel(
            "[yellow bold]Active mode enabled:[/yellow bold] Port scanning will send TCP packets to the target.\n"
            "Only use this on domains/systems you are authorized to test.",
            border_style="yellow",
        ))

    options = {
        "verbose": args.verbose,
        "active": args.active,
        "no_cache": args.no_cache,
        "json_only": args.json_only,
    }

    domain = clean_domain(args.domain)
    if not validate_domain(domain):
        if not args.json_only:
            console.print(f"[red]Invalid domain: {args.domain}[/red]")
            console.print("[dim]Domain should look like: example.com, sub.domain.co.uk[/dim]")
        else:
            print(json.dumps({"error": "invalid_domain", "domain": args.domain}))
        sys.exit(1)

    results = run_analysis(domain, options)

    if not results:
        if not args.json_only:
            console.print("[red]Analysis failed.[/red]")
        else:
            print(json.dumps({"error": "analysis_failed", "domain": domain}))
        sys.exit(1)

    if args.json_only:
        # Machine-readable JSON output to stdout
        print(json.dumps(results, indent=2, default=str))
    else:
        display_results(results)

    # Export if requested
    if args.output:
        export_results(results, args.output, args.fmt)

    sys.exit(0)


if __name__ == "__main__":
    main()
