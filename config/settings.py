#!/usr/bin/env python3
"""
Configuration globale pour NetTrace
"""

import os
from pathlib import Path

# Chemins
BASE_DIR = Path(__file__).parent.parent
CACHE_DIR = BASE_DIR / "cache"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Créer les dossiers nécessaires
for directory in [CACHE_DIR, REPORTS_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# Configuration cache
CACHE_ENABLED = True
CACHE_TTL = {
    'whois': 3600,      # 1 heure
    'dns': 300,         # 5 minutes
    'ssl': 1800,        # 30 minutes
    'http': 600,        # 10 minutes
    'geolocation': 86400 # 24 heures
}

# Configuration réseau
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 1  # secondes entre requêtes

# APIs externes (clés optionnelles)
API_KEYS = {
    'shodan': os.getenv('SHODAN_API_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'hibp': os.getenv('HIBP_API_KEY')
}

# Headers HTTP par défaut
DEFAULT_HEADERS = {
    'User-Agent': 'NetTrace/1.0 (OSINT Tool; +https://github.com/nettrace)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive'
}

# Configuration scoring
SCORING_WEIGHTS = {
    'trust': {
        'domain_age': 30,
        'dns_completeness': 25,
        'subdomains': 20,
        'whois_info': 15,
        'stability': 10
    },
    'security': {
        'ssl_certificate': 25,
        'security_headers': 30,
        'https_redirect': 15,
        'vulnerability_scan': 20,
        'reputation': 10
    }
}

# Listes de technologies à détecter
TECHNOLOGY_SIGNATURES = {
    'frameworks': {
        'React': ['react', '_react', 'react-dom'],
        'Angular': ['ng-', 'angular', '@angular'],
        'Vue.js': ['vue', '__vue__', 'vue.js'],
        'jQuery': ['jquery', '$', 'jQuery'],
        'Bootstrap': ['bootstrap', 'btn-', 'container-fluid'],
        'WordPress': ['wp-content', 'wp-includes', '/wp-json/']
    },
    'servers': {
        'Apache': ['Apache/', 'mod_'],
        'Nginx': ['nginx/', 'nginx'],
        'IIS': ['Microsoft-IIS/', 'X-Powered-By: ASP.NET'],
        'Cloudflare': ['cloudflare', 'cf-ray'],
        'AWS': ['AmazonS3', 'X-Amz-', 'cloudfront']
    },
    'analytics': {
        'Google Analytics': ['google-analytics', 'gtag', 'ga('],
        'Google Tag Manager': ['googletagmanager', 'GTM-'],
        'Facebook Pixel': ['fbevents.js', 'facebook.com/tr'],
        'Hotjar': ['hotjar', 'hj(']
    }
}

# Headers de sécurité à vérifier
SECURITY_HEADERS = {
    'Strict-Transport-Security': {'required': True, 'points': 10},
    'Content-Security-Policy': {'required': True, 'points': 15},
    'X-Frame-Options': {'required': True, 'points': 8},
    'X-Content-Type-Options': {'required': True, 'points': 5},
    'X-XSS-Protection': {'required': False, 'points': 3},
    'Referrer-Policy': {'required': False, 'points': 4},
    'Permissions-Policy': {'required': False, 'points': 5}
}

# Configuration notifications
NOTIFICATION_SETTINGS = {
    'email': {
        'enabled': False,
        'smtp_server': os.getenv('SMTP_SERVER'),
        'smtp_port': int(os.getenv('SMTP_PORT', 587)),
        'username': os.getenv('SMTP_USERNAME'),
        'password': os.getenv('SMTP_PASSWORD')
    },
    'webhook': {
        'enabled': False,
        'url': os.getenv('WEBHOOK_URL')
    }
}