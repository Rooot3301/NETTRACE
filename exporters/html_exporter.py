"""
NetTrace v2 - HTML Exporter
Generates a completely self-contained, offline-viewable HTML security report.
No external dependencies - all CSS and JS are inline.
"""
import json
from datetime import datetime
from typing import Dict, Any, List, Optional


def _esc(val) -> str:
    """HTML-escape a value."""
    if val is None:
        return ""
    s = str(val)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _fmt(val, default: str = "N/A") -> str:
    if val is None:
        return default
    s = str(val).strip()
    return _esc(s) if s else default


def _risk_color(risk_level: str) -> str:
    colors = {
        "LOW_RISK": "#2ecc71",
        "MEDIUM_RISK": "#f39c12",
        "ELEVATED_RISK": "#e67e22",
        "HIGH_RISK": "#e74c3c",
    }
    return colors.get(risk_level, "#95a5a6")


def _score_color(score: int) -> str:
    if score >= 80:
        return "#2ecc71"
    elif score >= 60:
        return "#f39c12"
    elif score >= 40:
        return "#e67e22"
    else:
        return "#e74c3c"


def _status_badge(text: str, color: str = "#2ecc71") -> str:
    return f'<span class="badge" style="background:{color}">{_esc(text)}</span>'


def _build_css() -> str:
    return """
    :root {
        --bg-primary: #0f1117;
        --bg-secondary: #1a1d26;
        --bg-card: #1e2130;
        --bg-card-hover: #252840;
        --border: #2d3250;
        --text-primary: #e8eaf6;
        --text-secondary: #9094b0;
        --text-dim: #5c6080;
        --accent: #5c6bc0;
        --accent-light: #7986cb;
        --green: #2ecc71;
        --yellow: #f39c12;
        --orange: #e67e22;
        --red: #e74c3c;
        --cyan: #00bcd4;
        --purple: #9c27b0;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        font-size: 14px;
    }

    a { color: var(--accent-light); text-decoration: none; }
    a:hover { text-decoration: underline; }

    .header {
        background: linear-gradient(135deg, #0f1117 0%, #1a1d26 50%, #0f1117 100%);
        border-bottom: 2px solid var(--accent);
        padding: 30px 40px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 20px;
    }

    .header-left h1 {
        font-size: 28px;
        font-weight: 700;
        color: var(--accent-light);
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    .header-left .subtitle {
        color: var(--text-secondary);
        font-size: 13px;
        margin-top: 4px;
    }

    .header-right {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 6px;
    }

    .domain-badge {
        font-size: 20px;
        font-weight: 600;
        color: var(--cyan);
        letter-spacing: 1px;
    }

    .date-badge {
        color: var(--text-secondary);
        font-size: 12px;
    }

    .score-gauge {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 4px;
    }

    .score-number {
        font-size: 36px;
        font-weight: 700;
        line-height: 1;
    }

    .score-label {
        font-size: 13px;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 4px;
        letter-spacing: 0.5px;
    }

    .score-bar-wrap {
        width: 200px;
        height: 8px;
        background: var(--border);
        border-radius: 4px;
        overflow: hidden;
    }

    .score-bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 1s ease;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 30px 20px;
    }

    .grid-2 {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(480px, 1fr));
        gap: 20px;
        margin-bottom: 20px;
    }

    .grid-3 {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-bottom: 20px;
    }

    .card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
        transition: border-color 0.2s;
    }

    .card:hover { border-color: var(--accent); }

    .card-header {
        background: linear-gradient(135deg, #1e2130, #252840);
        padding: 12px 18px;
        display: flex;
        align-items: center;
        gap: 10px;
        border-bottom: 1px solid var(--border);
    }

    .card-header h2 {
        font-size: 14px;
        font-weight: 600;
        color: var(--accent-light);
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .card-icon {
        width: 20px;
        height: 20px;
        opacity: 0.8;
    }

    .card-body { padding: 16px 18px; }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }

    th {
        background: #1a1d26;
        color: var(--text-secondary);
        padding: 8px 10px;
        text-align: left;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        border-bottom: 1px solid var(--border);
    }

    td {
        padding: 8px 10px;
        border-bottom: 1px solid rgba(45, 50, 80, 0.5);
        color: var(--text-primary);
        word-break: break-word;
    }

    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(92, 107, 192, 0.05); }

    .kv-table td:first-child {
        color: var(--text-secondary);
        font-weight: 500;
        width: 38%;
        white-space: nowrap;
    }

    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.4px;
        color: #fff;
    }

    .status-present { color: var(--green); font-weight: 600; }
    .status-missing { color: var(--red); font-weight: 600; }
    .status-warn { color: var(--yellow); font-weight: 600; }
    .status-info { color: var(--cyan); }

    .progress-bar {
        width: 100%;
        height: 6px;
        background: var(--border);
        border-radius: 3px;
        overflow: hidden;
        margin-top: 4px;
    }

    .progress-fill {
        height: 100%;
        border-radius: 3px;
    }

    .email-score-wrap {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 8px;
    }

    .email-score-num {
        font-size: 22px;
        font-weight: 700;
        min-width: 50px;
    }

    .email-score-bar {
        flex: 1;
        height: 10px;
        background: var(--border);
        border-radius: 5px;
        overflow: hidden;
    }

    .copy-btn {
        display: inline-block;
        padding: 2px 8px;
        background: var(--accent);
        color: #fff;
        border: none;
        border-radius: 3px;
        cursor: pointer;
        font-size: 11px;
        transition: background 0.2s;
    }

    .copy-btn:hover { background: var(--accent-light); }
    .copy-btn.copied { background: var(--green); }

    .dork-row td:first-child { font-family: 'Consolas', monospace; font-size: 12px; color: var(--yellow); }

    .summary-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }

    .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }

    .stat-value {
        font-size: 28px;
        font-weight: 700;
        color: var(--accent-light);
    }

    .stat-label {
        color: var(--text-secondary);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
    }

    .alert {
        border-left: 4px solid;
        padding: 10px 14px;
        border-radius: 0 4px 4px 0;
        margin-bottom: 8px;
        font-size: 13px;
    }

    .alert-danger { border-color: var(--red); background: rgba(231, 76, 60, 0.08); color: var(--red); }
    .alert-warn { border-color: var(--yellow); background: rgba(243, 156, 18, 0.08); color: var(--yellow); }
    .alert-info { border-color: var(--cyan); background: rgba(0, 188, 212, 0.08); color: var(--cyan); }
    .alert-success { border-color: var(--green); background: rgba(46, 204, 113, 0.08); color: var(--green); }

    .breakdown-row td:first-child { color: var(--text-secondary); }

    .section-full { margin-bottom: 20px; }

    code {
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        background: rgba(92, 107, 192, 0.1);
        padding: 1px 5px;
        border-radius: 3px;
        color: var(--cyan);
    }

    .tag {
        display: inline-block;
        padding: 2px 7px;
        border-radius: 3px;
        border: 1px solid var(--border);
        font-size: 11px;
        color: var(--text-secondary);
        margin: 2px;
    }

    .footer {
        background: var(--bg-secondary);
        border-top: 1px solid var(--border);
        padding: 20px 40px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        color: var(--text-dim);
        font-size: 12px;
        flex-wrap: wrap;
        gap: 10px;
    }

    @media (max-width: 768px) {
        .header { flex-direction: column; align-items: flex-start; }
        .grid-2, .grid-3 { grid-template-columns: 1fr; }
        .summary-stats { grid-template-columns: repeat(2, 1fr); }
    }
    """


def _build_js() -> str:
    return """
    function copyDork(btn, text) {
        navigator.clipboard.writeText(text).then(function() {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function() {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        }).catch(function() {
            var el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function() {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        });
    }
    """


def _whois_card(whois: Dict) -> str:
    if not whois:
        return '<div class="card-body"><p class="status-missing">WHOIS data unavailable</p></div>'

    def fd(val):
        if not val:
            return '<span style="color:var(--text-dim)">N/A</span>'
        try:
            dt = datetime.fromisoformat(str(val))
            return dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return _esc(str(val))

    age = whois.get("age_days")
    age_str = f"{age} days ({age // 365} yrs)" if age else "N/A"

    exp_days = whois.get("days_until_expiry")
    if exp_days is not None:
        if exp_days < 0:
            exp_str = f'<span class="status-missing">EXPIRED {abs(exp_days)}d ago</span>'
        elif exp_days < 30:
            exp_str = f'<span class="status-warn">Expires in {exp_days} days!</span>'
        else:
            exp_str = f'<span class="status-present">{exp_days} days</span>'
    else:
        exp_str = "N/A"

    ns = whois.get("name_servers", [])
    ns_html = " ".join(f'<span class="tag">{_esc(n)}</span>' for n in ns[:6])

    return f"""
    <div class="card-body">
    <table class="kv-table">
        <tr><td>Registrar</td><td>{_esc(whois.get('registrar') or 'N/A')}</td></tr>
        <tr><td>Created</td><td>{fd(whois.get('creation_date'))}</td></tr>
        <tr><td>Expires</td><td>{fd(whois.get('expiration_date'))}</td></tr>
        <tr><td>Updated</td><td>{fd(whois.get('updated_date'))}</td></tr>
        <tr><td>Domain Age</td><td>{_esc(age_str)}</td></tr>
        <tr><td>Days Until Expiry</td><td>{exp_str}</td></tr>
        <tr><td>Organization</td><td>{_esc(whois.get('registrant_org') or whois.get('registrant') or 'N/A')}</td></tr>
        <tr><td>Country</td><td>{_esc(whois.get('registrant_country') or 'N/A')}</td></tr>
        <tr><td>Name Servers</td><td>{ns_html or 'N/A'}</td></tr>
    </table>
    </div>"""


def _dns_card(dns: Dict) -> str:
    if not dns:
        return '<div class="card-body"><p class="status-missing">DNS data unavailable</p></div>'

    def recs(key, label):
        items = dns.get(key, [])
        if not items:
            return f'<tr><td>{label}</td><td><span style="color:var(--text-dim)">None</span></td></tr>'
        vals = "<br>".join(f"<code>{_esc(r)}</code>" for r in items[:5])
        if len(items) > 5:
            vals += f"<br><span style='color:var(--text-dim)'>+{len(items)-5} more</span>"
        return f"<tr><td>{label}</td><td>{vals}</td></tr>"

    dnssec = dns.get("dnssec_enabled", False)
    dnssec_html = '<span class="status-present">Enabled</span>' if dnssec else '<span class="status-missing">Disabled</span>'

    axfr_rows = ""
    for axfr in dns.get("axfr_results", []):
        ns = _esc(axfr.get("ns_name", axfr.get("ns", "")))
        if axfr.get("success"):
            status = f'<span class="status-missing">VULNERABLE - AXFR SUCCESS ({len(axfr.get("records",[]))} records)</span>'
        else:
            err = _esc(axfr.get("error", "blocked"))
            status = f'<span class="status-present">Blocked ({err})</span>'
        axfr_rows += f"<tr><td>{ns}</td><td>{status}</td></tr>"

    return f"""
    <div class="card-body">
    <table class="kv-table">
        {recs('a_records', 'A Records')}
        {recs('aaaa_records', 'AAAA Records')}
        {recs('mx_records', 'MX Records')}
        {recs('ns_records', 'NS Records')}
        {recs('cname_records', 'CNAME Records')}
        {recs('soa_records', 'SOA Records')}
        <tr><td>DNSSEC</td><td>{dnssec_html}</td></tr>
    </table>
    {"<h3 style='font-size:12px;color:var(--text-secondary);margin:12px 0 6px;text-transform:uppercase;letter-spacing:0.5px'>Zone Transfer Tests (AXFR)</h3><table><tr><th>Nameserver</th><th>Result</th></tr>" + axfr_rows + "</table>" if axfr_rows else ""}
    </div>"""


def _http_card(http: Dict) -> str:
    if not http:
        return '<div class="card-body"><p class="status-missing">HTTP data unavailable</p></div>'

    https_ok = http.get("https_reachable", False)
    https_str = '<span class="status-present">Yes</span>' if https_ok else '<span class="status-missing">No</span>'
    redirect = '<span class="status-present">Yes</span>' if http.get("redirect_to_https") else '<span class="status-warn">No</span>'

    waf = _esc(http.get("waf") or "None detected")
    cdn = _esc(http.get("cdn") or "None detected")
    server = _esc(http.get("server") or "N/A")
    powered = _esc(http.get("x_powered_by") or "N/A")
    techs = http.get("technologies", [])
    tech_html = " ".join(f'<span class="badge" style="background:var(--accent)">{_esc(t)}</span>' for t in techs) if techs else "None detected"

    hs = http.get("headers_score", 0)
    hs_color = _score_color(hs)
    hs_bar = f"""
    <div style="display:flex;align-items:center;gap:10px">
        <span style="font-weight:700;color:{hs_color};min-width:40px">{hs}/100</span>
        <div class="progress-bar" style="flex:1">
            <div class="progress-fill" style="width:{hs}%;background:{hs_color}"></div>
        </div>
    </div>"""

    # Security headers
    sec_headers = http.get("security_headers", {})
    all_sec_headers = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
    ]
    header_rows = ""
    for h in all_sec_headers:
        if h in sec_headers:
            val = sec_headers[h]
            short = (val[:60] + "...") if len(val) > 60 else val
            header_rows += f'<tr><td>{_esc(h)}</td><td><span class="status-present">Present</span></td><td><code>{_esc(short)}</code></td></tr>'
        else:
            header_rows += f'<tr><td>{_esc(h)}</td><td><span class="status-missing">Missing</span></td><td></td></tr>'

    # TLS
    tls = http.get("tls_info", {})
    tls_html = ""
    if tls and not tls.get("error"):
        days = tls.get("days_until_expiry")
        if days is not None:
            if days < 0:
                days_str = f'<span class="status-missing">EXPIRED {abs(days)}d ago</span>'
            elif days < 30:
                days_str = f'<span class="status-warn">{days} days (SOON!)</span>'
            else:
                days_str = f'<span class="status-present">{days} days</span>'
        else:
            days_str = "N/A"

        san = tls.get("san", [])
        san_html = ", ".join(f"<code>{_esc(s)}</code>" for s in san[:6])
        if len(san) > 6:
            san_html += f" <span style='color:var(--text-dim)'>+{len(san)-6} more</span>"

        tls_html = f"""
        <h3 style="font-size:12px;color:var(--text-secondary);margin:14px 0 6px;text-transform:uppercase;letter-spacing:0.5px">TLS Certificate</h3>
        <table class="kv-table">
            <tr><td>TLS Version</td><td><code>{_esc(tls.get('tls_version','N/A'))}</code></td></tr>
            <tr><td>Subject</td><td>{_esc(tls.get('subject','N/A'))}</td></tr>
            <tr><td>Issuer</td><td>{_esc(tls.get('issuer','N/A'))}</td></tr>
            <tr><td>Expires</td><td>{_esc(tls.get('not_after','N/A'))}</td></tr>
            <tr><td>Days Until Expiry</td><td>{days_str}</td></tr>
            <tr><td>SAN</td><td>{san_html or 'N/A'}</td></tr>
        </table>"""

    return f"""
    <div class="card-body">
    <table class="kv-table" style="margin-bottom:12px">
        <tr><td>HTTP Status</td><td>{_fmt(http.get('http_status'))}</td></tr>
        <tr><td>HTTPS Status</td><td>{_fmt(http.get('https_status'))}</td></tr>
        <tr><td>HTTPS Available</td><td>{https_str}</td></tr>
        <tr><td>HTTP→HTTPS Redirect</td><td>{redirect}</td></tr>
        <tr><td>Server</td><td><code>{server}</code></td></tr>
        <tr><td>X-Powered-By</td><td><code>{powered}</code></td></tr>
        <tr><td>WAF Detected</td><td>{waf}</td></tr>
        <tr><td>CDN (headers)</td><td>{cdn}</td></tr>
        <tr><td>Technologies</td><td>{tech_html}</td></tr>
        <tr><td>Security Headers Score</td><td>{hs_bar}</td></tr>
    </table>
    <h3 style="font-size:12px;color:var(--text-secondary);margin:14px 0 6px;text-transform:uppercase;letter-spacing:0.5px">Security Headers</h3>
    <table>
        <tr><th>Header</th><th>Status</th><th>Value</th></tr>
        {header_rows}
    </table>
    {tls_html}
    </div>"""


def _geo_card(geo: Dict) -> str:
    if not geo:
        return '<div class="card-body"><p class="status-missing">GeoIP data unavailable</p></div>'

    cdn_flag = ""
    if geo.get("is_behind_cdn"):
        cdn_flag = f'<div class="alert alert-info" style="margin-bottom:12px">CDN Detected: <strong>{_esc(geo.get("detected_cdn",""))}</strong></div>'

    countries = ", ".join(_esc(c) for c in geo.get("unique_countries", []))
    asns = ", ".join(_esc(a) for a in geo.get("unique_asns", []))

    ip_rows = ""
    for info in geo.get("ip_info", []):
        if info.get("status") == "success":
            cdn_val = info.get("cdn")
            cdn_cell = f'<span class="status-present">{_esc(cdn_val)}</span>' if cdn_val else '<span style="color:var(--text-dim)">No</span>'
            host_cell = '<span class="status-warn">Yes</span>' if info.get("hosting") else '<span style="color:var(--text-dim)">No</span>'
            ip_rows += f"""
            <tr>
                <td><code>{_esc(info.get('ip',''))}</code></td>
                <td>{_esc(info.get('country',''))}</td>
                <td>{_esc(info.get('city',''))}</td>
                <td><code style="font-size:11px">{_esc(info.get('as',''))}</code></td>
                <td>{_esc(info.get('org','') or info.get('isp',''))}</td>
                <td>{cdn_cell}</td>
                <td>{host_cell}</td>
            </tr>"""

    return f"""
    <div class="card-body">
    {cdn_flag}
    <table class="kv-table" style="margin-bottom:12px">
        <tr><td>Countries</td><td>{countries or 'N/A'}</td></tr>
        <tr><td>ASNs</td><td>{asns or 'N/A'}</td></tr>
    </table>
    <table>
        <tr><th>IP</th><th>Country</th><th>City</th><th>ASN</th><th>Organization</th><th>CDN</th><th>Hosting</th></tr>
        {ip_rows}
    </table>
    </div>"""


def _email_card(email: Dict) -> str:
    if not email:
        return '<div class="card-body"><p class="status-missing">Email security data unavailable</p></div>'

    es = email.get("email_score", 0)
    es_color = _score_color(es)

    spf = email.get("spf", {})
    dmarc = email.get("dmarc", {})
    dkim = email.get("dkim", {})
    bimi = email.get("bimi", {})
    mta = email.get("mta_sts", {})

    def check_status(found, policy=None, good_policy=None):
        if not found:
            return '<span class="status-missing">Missing</span>'
        if policy and good_policy and policy not in good_policy:
            return f'<span class="status-warn">Configured ({_esc(policy)})</span>'
        return f'<span class="status-present">Configured{(" (" + _esc(policy) + ")") if policy else ""}</span>'

    spf_policy = spf.get("policy")
    spf_color = "#e74c3c" if spf_policy == "pass_all" else ("#f39c12" if spf_policy == "softfail" else "#2ecc71")

    rows = [
        ("SPF", check_status(spf.get("found"), spf_policy, ["fail", "softfail"]),
         _esc(spf.get("record", "")[:80]) if spf.get("found") else ""),
        ("DMARC", check_status(dmarc.get("found"), dmarc.get("policy"), ["quarantine", "reject"]),
         f"pct={dmarc.get('pct',100)}%" if dmarc.get("found") else ""),
        ("DKIM", check_status(dkim.get("found"), None, None),
         f"Selectors: {', '.join(dkim.get('found_selectors',[])[:4])}" if dkim.get("found") else "No common selectors found"),
        ("BIMI", '<span class="status-present">Configured</span>' if bimi.get("found") else '<span style="color:var(--text-dim)">Not configured</span>', ""),
        ("MTA-STS", '<span class="status-present">Configured</span>' if mta.get("found") else '<span style="color:var(--text-dim)">Not configured</span>',
         _esc(f"ID: {mta.get('id')}" if mta.get("id") else "")),
    ]

    table_rows = ""
    for check, status, detail in rows:
        table_rows += f"<tr><td>{_esc(check)}</td><td>{status}</td><td><small style='color:var(--text-dim)'>{detail}</small></td></tr>"

    issues = email.get("issues", [])
    issues_html = ""
    if issues:
        issues_html = "".join(
            f'<div class="alert alert-warn">{_esc(i)}</div>' for i in issues
        )

    return f"""
    <div class="card-body">
    <div class="email-score-wrap">
        <span class="email-score-num" style="color:{es_color}">{es}</span>
        <div style="flex:1">
            <div style="font-size:11px;color:var(--text-dim);margin-bottom:3px">Email Security Score</div>
            <div class="email-score-bar">
                <div class="progress-fill" style="width:{es}%;background:{es_color}"></div>
            </div>
        </div>
        <span style="color:var(--text-secondary);font-size:12px">/100</span>
    </div>
    <table style="margin:12px 0">
        <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
        {table_rows}
    </table>
    {issues_html}
    </div>"""


def _subdomains_card(subs: Dict) -> str:
    if not subs:
        return '<div class="card-body"><p class="status-missing">Subdomain data unavailable</p></div>'

    count = subs.get("total_count", 0)
    sources = subs.get("sources", {})
    src_html = " ".join(
        f'<span class="tag">{_esc(src)}: {cnt}</span>' for src, cnt in sources.items()
    )

    sub_list = subs.get("subdomains", [])
    sub_rows = ""
    for i, sub in enumerate(sub_list[:40], 1):
        sub_rows += f'<tr><td style="color:var(--text-dim);width:30px">{i}</td><td><code>{_esc(sub)}</code></td></tr>'
    if len(sub_list) > 40:
        sub_rows += f'<tr><td colspan="2" style="color:var(--text-dim);text-align:center">... and {len(sub_list)-40} more</td></tr>'

    takeover = subs.get("takeover_candidates", [])
    takeover_html = ""
    if takeover:
        to_rows = ""
        for t in takeover:
            confirmed = t.get("confirmed", False)
            conf_str = '<span class="status-missing">CONFIRMED</span>' if confirmed else '<span class="status-warn">Possible</span>'
            to_rows += f"""
            <tr>
                <td><code>{_esc(t.get('subdomain',''))}</code></td>
                <td><code>{_esc(t.get('cname',''))}</code></td>
                <td>{_esc(t.get('service',''))}</td>
                <td>{conf_str}</td>
            </tr>"""
        takeover_html = f"""
        <div class="alert alert-danger" style="margin-bottom:12px">
            <strong>{len(takeover)} potential subdomain takeover candidate(s) detected!</strong>
        </div>
        <table>
            <tr><th>Subdomain</th><th>CNAME Target</th><th>Service</th><th>Confirmed</th></tr>
            {to_rows}
        </table>"""

    return f"""
    <div class="card-body">
    <div style="margin-bottom:12px">
        <span class="stat-value" style="font-size:24px">{count}</span>
        <span style="color:var(--text-secondary);margin-left:8px">subdomains found</span>
    </div>
    <div style="margin-bottom:14px">{src_html}</div>
    {takeover_html}
    {"<table><tr><th>#</th><th>Subdomain</th></tr>" + sub_rows + "</table>" if sub_rows else ""}
    </div>"""


def _archive_card(archive: Dict) -> str:
    if not archive:
        return '<div class="card-body"><p class="status-missing">Archive data unavailable</p></div>'

    avail = archive.get("available", False)
    avail_str = '<span class="status-present">Yes</span>' if avail else '<span class="status-missing">No</span>'
    wb_url = archive.get("wayback_url", "")
    wb_link = f'<a href="{_esc(wb_url)}" target="_blank">{_esc(wb_url[:60])}</a>' if wb_url else "N/A"

    interesting = archive.get("interesting_urls", [])
    int_rows = ""
    for url in interesting[:20]:
        int_rows += f'<tr><td><a href="{_esc(url)}" target="_blank" style="color:var(--yellow)">{_esc(url[:80])}</a></td></tr>'

    int_html = ""
    if int_rows:
        int_html = f"""
        <h3 style="font-size:12px;color:var(--text-secondary);margin:14px 0 6px;text-transform:uppercase;letter-spacing:0.5px">Interesting Archived URLs ({len(interesting)})</h3>
        <table><tr><th>URL</th></tr>{int_rows}</table>"""

    return f"""
    <div class="card-body">
    <table class="kv-table" style="margin-bottom:12px">
        <tr><td>Available</td><td>{avail_str}</td></tr>
        <tr><td>First Seen</td><td>{_fmt(archive.get('first_seen'))}</td></tr>
        <tr><td>Last Seen</td><td>{_fmt(archive.get('last_seen'))}</td></tr>
        <tr><td>Total Snapshots</td><td>~{_fmt(archive.get('snapshot_count'))}</td></tr>
        <tr><td>Latest Snapshot</td><td>{wb_link}</td></tr>
    </table>
    {int_html}
    </div>"""


def _ports_card(ports: Dict) -> str:
    if not ports:
        return '<div class="card-body"><p style="color:var(--text-dim)">Port scan not performed (requires --active flag)</p></div>'

    open_ports = ports.get("open_ports", [])
    if not open_ports:
        return '<div class="card-body"><div class="alert alert-success">No open ports found on scanned ports.</div></div>'

    dangerous = {23, 21, 3389, 445, 3306, 5432}
    rows = ""
    for p in open_ports:
        port = p.get("port", 0)
        service = _esc(p.get("service", "Unknown"))
        ip = _esc(p.get("ip", ""))
        banner = _esc(p.get("banner") or "N/A")
        port_color = "var(--red)" if port in dangerous else "var(--green)"
        rows += f"""
        <tr>
            <td><span style="color:{port_color};font-weight:700">{port}</span></td>
            <td>{service}</td>
            <td><code>{ip}</code></td>
            <td style="font-size:12px;color:var(--text-dim)">{banner}</td>
        </tr>"""

    return f"""
    <div class="card-body">
    <p style="color:var(--text-secondary);margin-bottom:12px">Open ports: <strong style="color:var(--cyan)">{len(open_ports)}</strong></p>
    <table>
        <tr><th>Port</th><th>Service</th><th>IP</th><th>Banner</th></tr>
        {rows}
    </table>
    </div>"""


def _scoring_card(scoring: Dict) -> str:
    if not scoring:
        return '<div class="card-body"><p class="status-missing">Scoring data unavailable</p></div>'

    score = scoring.get("score", 0)
    risk_level = scoring.get("risk_level", "HIGH_RISK")
    risk_label = scoring.get("risk_label", "High Risk")
    color = _risk_color(risk_level)

    breakdown = scoring.get("breakdown", {})
    label_map = {
        "domain_age": "Domain Age",
        "dns_completeness": "DNS Completeness",
        "email_security": "Email Security",
        "https_headers": "HTTPS / Security Headers",
        "subdomain_presence": "Subdomain Presence",
        "whois_completeness": "WHOIS Completeness",
        "archive_presence": "Archive Presence",
    }

    breakdown_rows = ""
    for key, data in breakdown.items():
        s = data.get("score", 0)
        m = data.get("max", 0)
        detail = _esc(data.get("detail", ""))
        pct = int((s / m * 100)) if m else 0
        bar_color = _score_color(pct)
        bar = f'<div class="progress-bar" style="width:120px;display:inline-block"><div class="progress-fill" style="width:{pct}%;background:{bar_color}"></div></div>'
        breakdown_rows += f"""
        <tr class="breakdown-row">
            <td>{_esc(label_map.get(key, key))}</td>
            <td style="text-align:center;color:{bar_color};font-weight:700">{s}/{m}</td>
            <td>{bar}</td>
            <td style="font-size:12px;color:var(--text-dim)">{detail}</td>
        </tr>"""

    recs = scoring.get("recommendations", [])
    rec_html = ""
    for rec in recs:
        if "CRITICAL" in rec:
            rec_html += f'<div class="alert alert-danger">{_esc(rec)}</div>'
        elif "EXPIRING" in rec or "takeover" in rec.lower() or "WARNING" in rec:
            rec_html += f'<div class="alert alert-warn">{_esc(rec)}</div>'
        elif "good" in rec.lower():
            rec_html += f'<div class="alert alert-success">{_esc(rec)}</div>'
        else:
            rec_html += f'<div class="alert alert-info">{_esc(rec)}</div>'

    # Gauge visual using CSS
    gauge_fill = int((score / 100) * 280)  # max degrees = 180 degrees arc
    bar_width = score

    return f"""
    <div class="card-body">
    <div style="display:flex;align-items:center;gap:24px;margin-bottom:20px;flex-wrap:wrap">
        <div style="text-align:center">
            <div style="font-size:56px;font-weight:700;color:{color};line-height:1">{score}</div>
            <div style="color:var(--text-secondary);font-size:12px">out of 100</div>
        </div>
        <div style="flex:1;min-width:200px">
            <div style="font-size:18px;font-weight:600;color:{color};margin-bottom:8px">{_esc(risk_label)}</div>
            <div class="progress-bar" style="height:12px">
                <div class="progress-fill" style="width:{bar_width}%;background:{color}"></div>
            </div>
            <div style="display:flex;justify-content:space-between;margin-top:4px;font-size:11px;color:var(--text-dim)">
                <span>0 (High Risk)</span>
                <span>100 (Low Risk)</span>
            </div>
        </div>
    </div>
    <table style="margin-bottom:16px">
        <tr><th>Category</th><th style="text-align:center">Score</th><th>Progress</th><th>Detail</th></tr>
        {breakdown_rows}
    </table>
    <h3 style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;text-transform:uppercase;letter-spacing:0.5px">Recommendations</h3>
    {rec_html}
    </div>"""


def _dorks_section(dorks_data: Dict) -> str:
    if not dorks_data:
        return ""

    dorks = dorks_data.get("dorks", {})
    sections = ""
    for category, dork_list in dorks.items():
        rows = ""
        for dork in dork_list:
            dork_escaped = _esc(dork)
            dork_js = dork.replace("'", "\\'").replace("\\", "\\\\")
            rows += f"""
            <tr class="dork-row">
                <td>{dork_escaped}</td>
                <td style="white-space:nowrap;text-align:right">
                    <button class="copy-btn" onclick="copyDork(this, '{dork_js}')">Copy</button>
                    <a href="https://www.google.com/search?q={_esc(dork)}" target="_blank" style="margin-left:6px;font-size:11px">Search</a>
                </td>
            </tr>"""
        sections += f"""
        <div class="card" style="margin-bottom:12px">
            <div class="card-header"><h2>{_esc(category)}</h2></div>
            <div class="card-body" style="padding:0">
                <table>
                    <tr><th>Dork Query</th><th style="text-align:right;white-space:nowrap">Actions</th></tr>
                    {rows}
                </table>
            </div>
        </div>"""

    return f"""
    <div class="section-full" id="dorks">
        <div class="card">
            <div class="card-header">
                <h2>Google Dorks</h2>
            </div>
        </div>
        <div style="margin-top:12px">{sections}</div>
        <div class="alert alert-info" style="margin-top:8px">
            These dork queries can be used in Google to discover exposed information. Use responsibly and only on domains you are authorized to test.
        </div>
    </div>"""


def _summary_stats(results: Dict) -> str:
    dns = results.get("dns", {})
    subs = results.get("subdomains", {})
    email = results.get("email", {})
    ports = results.get("ports", {})
    scoring = results.get("scoring", {})
    http = results.get("http", {})

    ip_count = len(dns.get("a_records", []))
    sub_count = subs.get("total_count", 0)
    open_ports_count = len(ports.get("open_ports", [])) if ports else "N/A"
    email_score = email.get("email_score", 0) if email else 0
    risk_score = scoring.get("score", 0)
    risk_color = _risk_color(scoring.get("risk_level", "HIGH_RISK"))
    https_badge = "Yes" if http and http.get("https_reachable") else "No"
    https_color = "var(--green)" if https_badge == "Yes" else "var(--red)"

    stats = [
        ("Risk Score", f'<span style="color:{risk_color};font-size:28px;font-weight:700">{risk_score}/100</span>', ""),
        ("IP Addresses", str(ip_count), "var(--cyan)"),
        ("Subdomains", str(sub_count), "var(--accent-light)"),
        ("Email Score", str(email_score) + "/100", _score_color(email_score)),
        ("HTTPS", https_badge, https_color),
        ("Open Ports", str(open_ports_count), "var(--yellow)"),
    ]

    cards = ""
    for label, value, color in stats:
        if color:
            val_html = f'<div class="stat-value" style="color:{color}">{value}</div>'
        else:
            val_html = f'<div>{value}</div>'
        cards += f"""
        <div class="stat-card">
            {val_html}
            <div class="stat-label">{_esc(label)}</div>
        </div>"""

    return f'<div class="summary-stats">{cards}</div>'


def _card_wrap(title: str, content: str, icon: str = "") -> str:
    icon_html = f'<span style="font-size:16px;margin-right:2px">{icon}</span>' if icon else ""
    return f"""
    <div class="card">
        <div class="card-header">
            {icon_html}
            <h2>{_esc(title)}</h2>
        </div>
        {content}
    </div>"""


def export_html(results: Dict[str, Any], filename: str) -> bool:
    """
    Export full analysis results as a self-contained HTML report.

    Args:
        results: complete analysis results dict
        filename: output file path

    Returns:
        True on success, False on failure
    """
    try:
        domain = results.get("domain", "unknown")
        analysis_date = results.get("analysis_date", datetime.utcnow().isoformat())
        try:
            dt = datetime.fromisoformat(str(analysis_date))
            date_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, TypeError):
            date_str = str(analysis_date)

        scoring = results.get("scoring", {})
        score = scoring.get("score", 0)
        risk_level = scoring.get("risk_level", "HIGH_RISK")
        risk_label = scoring.get("risk_label", "Unknown")
        risk_color = _risk_color(risk_level)
        score_color = _score_color(score)

        vt_url = f"https://www.virustotal.com/gui/domain/{domain}/detection"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetTrace Report - {_esc(domain)}</title>
    <style>
    {_build_css()}
    </style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>NetTrace v2</h1>
        <div class="subtitle">Advanced OSINT Domain Analysis Report</div>
    </div>
    <div class="header-right">
        <div class="domain-badge">{_esc(domain)}</div>
        <div class="date-badge">Analyzed: {_esc(date_str)}</div>
        <div class="score-gauge">
            <span class="score-number" style="color:{score_color}">{score}</span>
            <div>
                <div class="score-label" style="background:{risk_color}20;color:{risk_color};border:1px solid {risk_color}">{_esc(risk_label)}</div>
                <div class="score-bar-wrap" style="margin-top:6px">
                    <div class="score-bar-fill" style="width:{score}%;background:{score_color}"></div>
                </div>
            </div>
        </div>
        <div style="margin-top:6px">
            <a href="{_esc(vt_url)}" target="_blank" style="font-size:12px;color:var(--accent-light)">View on VirusTotal</a>
        </div>
    </div>
</div>

<div class="container">

{_summary_stats(results)}

<div class="grid-2">
    {_card_wrap("WHOIS Information", _whois_card(results.get("whois", {})), "📋")}
    {_card_wrap("DNS Records", _dns_card(results.get("dns", {})), "🌐")}
</div>

<div class="section-full">
    {_card_wrap("HTTP / TLS Analysis", _http_card(results.get("http", {})), "🔒")}
</div>

<div class="grid-2">
    {_card_wrap("GeoIP Analysis", _geo_card(results.get("geo", {})), "📍")}
    {_card_wrap("Email Security", _email_card(results.get("email", {})), "📧")}
</div>

<div class="grid-2">
    {_card_wrap("Subdomain Enumeration", _subdomains_card(results.get("subdomains", {})), "🔍")}
    {_card_wrap("Wayback Machine Archive", _archive_card(results.get("archive", {})), "📦")}
</div>

<div class="section-full">
    {_card_wrap("Port Scan Results", _ports_card(results.get("ports")), "🔌")}
</div>

<div class="section-full">
    {_card_wrap("Risk Assessment", _scoring_card(results.get("scoring", {})), "⚠️")}
</div>

{_dorks_section(results.get("dorks", {}))}

</div>

<div class="footer">
    <div>
        <strong>NetTrace v2</strong> - Advanced OSINT Domain Analysis Tool &nbsp;|&nbsp;
        Domain: <strong>{_esc(domain)}</strong>
    </div>
    <div>
        Report generated: {_esc(date_str)} &nbsp;|&nbsp;
        <a href="{_esc(vt_url)}" target="_blank">VirusTotal</a> &nbsp;|&nbsp;
        <a href="https://web.archive.org/web/*/{_esc(domain)}" target="_blank">Wayback Machine</a>
    </div>
</div>

<script>
{_build_js()}
</script>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        return True

    except (OSError, TypeError, AttributeError) as e:
        return False
