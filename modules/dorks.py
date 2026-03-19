"""
NetTrace v2 - Google Dorks Generator Module
Generates categorized Google Dorks for OSINT investigation of a domain.
"""
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def generate_dorks(domain: str) -> Dict[str, Any]:
    """
    Generate categorized Google Dorks for a domain.

    Returns dict with categories as keys, each containing a list of dork strings.
    """
    dorks: Dict[str, List[str]] = {
        "Sensitive Files": [
            f"site:{domain} filetype:pdf",
            f"site:{domain} ext:sql OR ext:bak OR ext:env",
            f"site:{domain} ext:log",
            f"site:{domain} filetype:xml",
            f"site:{domain} ext:yaml OR ext:yml",
            f"site:{domain} ext:conf OR ext:cfg",
            f"site:{domain} ext:ini",
            f"site:{domain} filetype:txt inurl:readme",
        ],
        "Admin Panels": [
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} inurl:dashboard",
            f"site:{domain} inurl:wp-admin",
            f"site:{domain} inurl:administrator",
            f"site:{domain} inurl:controlpanel",
            f"site:{domain} inurl:cpanel",
            f"site:{domain} inurl:manage",
        ],
        "Exposed Information": [
            f"site:{domain} intext:password",
            f'"@{domain}" ext:csv OR ext:xlsx',
            f"site:{domain} inurl:config",
            f"site:{domain} intext:\"api_key\" OR intext:\"apikey\"",
            f"site:{domain} intext:\"secret_key\"",
            f"site:{domain} intext:\"token\"",
            f"site:{domain} intext:\"private_key\"",
            f"site:{domain} intext:\"BEGIN RSA PRIVATE KEY\"",
        ],
        "Source Code / Dev": [
            f"site:{domain} inurl:.git",
            f"site:{domain} inurl:phpinfo",
            f"site:{domain} inurl:test",
            f"site:{domain} inurl:dev",
            f"site:{domain} inurl:staging",
            f"site:{domain} inurl:debug",
            f"site:{domain} ext:php inurl:?",
            f"site:{domain} inurl:swagger OR inurl:api-docs",
        ],
        "Third Party Mentions": [
            f'site:pastebin.com "{domain}"',
            f'site:github.com "{domain}"',
            f'site:reddit.com "{domain}"',
            f'site:stackoverflow.com "{domain}"',
            f'site:linkedin.com "{domain}"',
            f'site:twitter.com "{domain}"',
            f'"{domain}" intext:password site:pastebin.com',
            f'site:trello.com "{domain}"',
        ],
        "Subdomains": [
            f"site:*.{domain}",
            f"site:{domain} -www",
            f"site:*.{domain} -www.{domain}",
            f"site:mail.{domain} OR site:vpn.{domain} OR site:ftp.{domain}",
            f"site:dev.{domain} OR site:staging.{domain} OR site:test.{domain}",
            f"site:api.{domain} OR site:beta.{domain}",
        ],
        "Vulnerabilities": [
            f"site:{domain} inurl:\"?id=\" OR inurl:\"?page=\" OR inurl:\"?cat=\"",
            f"site:{domain} inurl:redirect?url=",
            f"site:{domain} inurl:search?q=",
            f"site:{domain} inurl:download?file=",
            f"site:{domain} inurl:include?file=",
            f"site:{domain} inurl:upload",
        ],
        "Cache / Indexed": [
            f"cache:{domain}",
            f"info:{domain}",
            f"related:{domain}",
            f"link:{domain}",
        ],
    }

    return {
        "domain": domain,
        "dorks": dorks,
        "total_count": sum(len(v) for v in dorks.values()),
    }


def display_dorks(dorks_result: Dict[str, Any]) -> None:
    """Display dorks with rich tables, one per category."""
    domain = dorks_result.get("domain", "")
    dorks = dorks_result.get("dorks", {})

    for category, dork_list in dorks.items():
        table = Table(
            title=f"[bold cyan]{category}[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            expand=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Dork Query", style="yellow", overflow="fold")

        for i, dork in enumerate(dork_list, 1):
            table.add_row(str(i), dork)

        console.print(table)

    console.print(
        Panel(
            f"[dim]Copy and paste these queries into Google search to find exposed information.\n"
            f"Total dorks generated: [bold]{dorks_result.get('total_count', 0)}[/bold][/dim]",
            title="[bold yellow]Google Dorks - Usage Note[/bold yellow]",
            border_style="yellow",
        )
    )
