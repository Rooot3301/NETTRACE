"""
NetTrace v2 - Configuration
"""
from pathlib import Path

# Cache configuration
CACHE_DIR = Path.home() / ".nettrace" / "cache"
CACHE_TTL = 86400  # 24 hours in seconds

# Network timeouts
DEFAULT_TIMEOUT = 10
PORT_SCAN_TIMEOUT = 1

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443, 8888
]

# Port service name mapping
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
}

# Subdomain takeover fingerprints
# Key = CNAME target pattern, Value = HTTP response body fingerprint
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "githubusercontent.com": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "s3-website": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "azure.com": "404 Web Site not found",
    "zendesk.com": "Help Center Closed",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
    "surge.sh": "project not found",
    "readme.io": "Project doesnt exist",
    "ghost.io": "The thing you were looking for is no longer here",
    "netlify.com": "Not Found - Request ID",
    "netlify.app": "Not Found - Request ID",
    "wordpress.com": "Do you want to register",
    "wp.com": "Do you want to register",
    "tumblr.com": "Whatever you were looking for doesn't currently exist",
    "webflow.io": "The page you are looking for doesn't exist",
    "squarespace.com": "No Such Account",
    "wix.com": "Error ConnectYourDomain",
    "bitbucket.io": "Repository not found",
    "smugmug.com": "Page Not Found",
    "helpjuice.com": "We could not find what you're looking for",
    "helpscoutdocs.com": "No settings were found for this company",
    "intercom.io": "This page is reserved for artistic dogs",
    "pantheon.io": "The gods are wise",
    "unbounce.com": "The requested URL was not found on this server",
    "statuspage.io": "You are being",
    "pingdom.com": "Sorry, couldn't find the status page",
    "freshdesk.com": "There is no helpdesk here",
    "campaign-archive.com": "Oops! We can't find that page",
}

# WAF detection signatures
WAF_SIGNATURES = {
    "cloudflare": "cloudflare",
    "Cloudflare": "Cloudflare",
    "__cfduid": "Cloudflare",
    "cf-ray": "Cloudflare",
    "X-Sucuri-ID": "Sucuri",
    "X-Sucuri-Cache": "Sucuri",
    "X-Sucuri-Block": "Sucuri",
    "X-Akamai-Transformed": "Akamai",
    "AkamaiGHost": "Akamai",
    "X-Distil-CS": "Distil Networks",
    "X-DT-WL": "Distil Networks",
    "X-Barracuda-Connect": "Barracuda",
    "X-Wallarm-Result": "Wallarm",
    "X-SL-CompState": "Incapsula",
    "X-Iinfo": "Incapsula",
    "visid_incap": "Incapsula",
    "incap_ses": "Incapsula",
    "X-F5-Request-ID": "F5 BIG-IP",
    "X-WPE-Request-ID": "WP Engine",
    "X-Denied-Reason": "Akamai",
    "X-Check-Cacheable": "Varnish",
    "X-Varnish": "Varnish",
    "Powered-By-ChinaCache": "ChinaCache",
    "FORTIWAFSID": "FortiWeb",
    "F5_fullWT": "F5 BIG-IP",
    "TS": "F5 BIG-IP ASM",
    "X-PolySwarm-WAS": "PolySwarm",
}

# CDN provider signatures (check against org/ASN from GeoIP)
CDN_SIGNATURES = {
    "Cloudflare": ["cloudflare", "CLOUDFLARENET"],
    "Akamai": ["akamai", "AKAMAI"],
    "Fastly": ["fastly", "FASTLY"],
    "Amazon CloudFront": ["cloudfront", "amazon", "AMAZON-02", "AWS"],
    "Google": ["google", "GOOGLE", "AS15169"],
    "Microsoft Azure CDN": ["microsoft", "azure", "MICROSOFT-CORP"],
    "StackPath": ["stackpath", "highwinds", "STACKPATH"],
    "KeyCDN": ["keycdn", "KEYCDN"],
    "Bunny CDN": ["bunnycdn", "BunnyCDN"],
    "CDN77": ["cdn77", "DATACAMP"],
    "MaxCDN / StackPath": ["maxcdn", "stackpath"],
    "Imperva / Incapsula": ["incapsula", "imperva", "INCAPSULA"],
    "Limelight": ["limelight", "LLNW"],
    "Rackspace": ["rackspace", "RACKSPACE"],
    "Sucuri": ["sucuri", "SUCURI"],
}

# Version info
VERSION = "2.0"
TOOL_NAME = "NetTrace"
AUTHOR = "OSINT Research Tool"
