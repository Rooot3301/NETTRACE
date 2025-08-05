#!/usr/bin/env python3
"""
Production configuration for NetTrace
Optimized settings with security and performance focus
"""

import os
from pathlib import Path
import logging

# Chemins
BASE_DIR = Path(__file__).parent.parent
CACHE_DIR = BASE_DIR / "cache"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Créer les dossiers nécessaires
for directory in [CACHE_DIR, REPORTS_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# Configuration logging production
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = LOGS_DIR / 'nettrace.log'

# Rotation des logs
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5

# Configuration cache
CACHE_ENABLED = True
CACHE_TTL = {
    'whois': 3600,        # 1 heure
    'dns': 300,           # 5 minutes
    'ssl': 1800,          # 30 minutes
    'http': 600,          # 10 minutes
    'geolocation': 86400, # 24 heures
    'reputation': 7200    # 2 heures
}

# Configuration réseau optimisée
REQUEST_TIMEOUT = 10  # Réduit pour la production
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 0.5  # Optimisé
MAX_CONCURRENT_REQUESTS = 5

# Configuration sécurité
MAX_DOMAIN_LENGTH = 253
MAX_SUBDOMAINS_DISPLAY = 10
MAX_DNS_RECORDS_DISPLAY = 5
ALLOWED_PROTOCOLS = ['http', 'https']

# Validation stricte des entrées
DOMAIN_REGEX = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'

# Blacklist de domaines à éviter
DOMAIN_BLACKLIST = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'example.test',
    'test.local'
]

# APIs externes (clés optionnelles)
API_KEYS = {
    'shodan': os.getenv('SHODAN_API_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'hibp': os.getenv('HIBP_API_KEY'),
    'urlvoid': os.getenv('URLVOID_API_KEY')
}

# Headers HTTP sécurisés
DEFAULT_HEADERS = {
    'User-Agent': 'NetTrace/1.0 (Security Research Tool; +https://github.com/nettrace)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'DNT': '1',  # Do Not Track
    'Upgrade-Insecure-Requests': '1'
}

# Configuration scoring optimisée
SCORING_WEIGHTS = {
    'trust': {
        'domain_age': 30,
        'dns_completeness': 25,
        'subdomains': 20,
        'whois_info': 15,
        'stability': 10
    },
    'security': {
        'ssl_certificate': 30,
        'security_headers': 30,
        'https_redirect': 15,
        'modern_protocols': 15,
        'security_features': 10
    },
    'reputation': {
        'blacklist_check': 40,
        'certificate_transparency': 25,
        'domain_reputation': 20,
        'historical_data': 15
    }
}

# Technologies détectées (optimisé)
TECHNOLOGY_SIGNATURES = {
    'frameworks': {
        'React': ['react', '_react', 'react-dom'],
        'Angular': ['ng-', 'angular', '@angular'],
        'Vue.js': ['vue', '__vue__', 'vue.js'],
        'jQuery': ['jquery', '$', 'jQuery'],
        'Bootstrap': ['bootstrap', 'btn-', 'container-fluid', 'bootstrap.min.css'],
        'Tailwind': ['tailwindcss', 'tailwind.css', 'tw-'],
        'Next.js': ['_next', '__next', 'next.js'],
        'Nuxt.js': ['_nuxt', '__nuxt', 'nuxt.js']
    },
    'servers': {
        'Apache': ['Apache/', 'mod_'],
        'Nginx': ['nginx/', 'nginx'],
        'IIS': ['Microsoft-IIS/', 'X-Powered-By: ASP.NET'],
        'LiteSpeed': ['LiteSpeed', 'X-LiteSpeed-Cache'],
        'Caddy': ['Caddy', 'caddy']
    },
    'cdn': {
        'Cloudflare': ['cloudflare', 'cf-ray', '__cf_bm'],
        'AWS CloudFront': ['AmazonS3', 'X-Amz-', 'cloudfront'],
        'Fastly': ['fastly', 'x-served-by'],
        'KeyCDN': ['keycdn', 'x-edge-location'],
        'MaxCDN': ['maxcdn', 'x-cache']
    },
    'analytics': {
        'Google Analytics': ['google-analytics', 'gtag', 'ga('],
        'Google Tag Manager': ['googletagmanager', 'GTM-'],
        'Facebook Pixel': ['fbevents.js', 'facebook.com/tr'],
        'Hotjar': ['hotjar', 'hj('],
        'Matomo': ['matomo', 'piwik'],
        'Adobe Analytics': ['adobe', 's_code.js']
    },
    'cms': {
        'WordPress': ['wp-content', 'wp-includes', '/wp-json/', 'wp-admin'],
        'Drupal': ['drupal', '/sites/default/', 'drupal.js'],
        'Joomla': ['joomla', '/media/jui/', '/administrator/'],
        'Shopify': ['shopify', 'cdn.shopify.com', 'shopify-checkout'],
        'Magento': ['magento', '/skin/frontend/', 'mage/cookies'],
        'PrestaShop': ['prestashop', '/modules/'],
        'Ghost': ['ghost', '/ghost/api/'],
        'Strapi': ['strapi', '/strapi/']
    }
}

# Headers de sécurité critiques
SECURITY_HEADERS = {
    'Strict-Transport-Security': {'required': True, 'points': 15},
    'Content-Security-Policy': {'required': True, 'points': 15},
    'X-Frame-Options': {'required': True, 'points': 10},
    'X-Content-Type-Options': {'required': True, 'points': 8},
    'Referrer-Policy': {'required': True, 'points': 7},
    'Permissions-Policy': {'required': False, 'points': 5},
    'X-XSS-Protection': {'required': False, 'points': 3},
    'Cross-Origin-Embedder-Policy': {'required': False, 'points': 4},
    'Cross-Origin-Opener-Policy': {'required': False, 'points': 3}
}

# Configuration notifications (production)
NOTIFICATION_SETTINGS = {
    'email': {
        'enabled': bool(os.getenv('SMTP_SERVER')),
        'smtp_server': os.getenv('SMTP_SERVER'),
        'smtp_port': int(os.getenv('SMTP_PORT', 587)),
        'username': os.getenv('SMTP_USERNAME'),
        'password': os.getenv('SMTP_PASSWORD'),
        'use_tls': True,
        'timeout': 30
    },
    'webhook': {
        'enabled': bool(os.getenv('WEBHOOK_URL')),
        'url': os.getenv('WEBHOOK_URL'),
        'timeout': 10,
        'retry_count': 3
    },
    'slack': {
        'enabled': bool(os.getenv('SLACK_WEBHOOK_URL')),
        'webhook_url': os.getenv('SLACK_WEBHOOK_URL'),
        'channel': os.getenv('SLACK_CHANNEL', '#nettrace'),
        'username': 'NetTrace Bot'
    }
}

# Configuration monitoring
MONITORING_SETTINGS = {
    'enabled': True,
    'check_interval': 3600,  # 1 heure
    'max_domains': 100,
    'alert_threshold': {
        'dns_changes': 1,
        'ssl_changes': 1,
        'whois_changes': 1
    }
}

# Configuration export
EXPORT_SETTINGS = {
    'max_file_size': 50 * 1024 * 1024,  # 50MB
    'allowed_formats': ['json', 'html', 'csv', 'xml', 'txt'],
    'html_template': 'modern',
    'include_raw_data': False,
    'compress_large_files': True
}

# Configuration performance
PERFORMANCE_SETTINGS = {
    'enable_compression': True,
    'cache_compression': True,
    'parallel_dns_queries': True,
    'max_workers': 10,
    'memory_limit': 512 * 1024 * 1024,  # 512MB
    'gc_threshold': 1000
}

# URLs de services externes
EXTERNAL_SERVICES = {
    'crt_sh': 'https://crt.sh/?q={domain}&output=json',
    'ip_api': 'http://ip-api.com/json/{ip}',
    'virustotal': 'https://www.virustotal.com/api/v3/domains/{domain}',
    'urlvoid': 'https://api.urlvoid.com/v1/pay-as-you-go/',
    'phishtank': 'https://checkurl.phishtank.com/checkurl/',
    'shodan': 'https://api.shodan.io/dns/domain/{domain}'
}

# Configuration développement vs production
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')

if ENVIRONMENT == 'development':
    REQUEST_TIMEOUT = 30
    RATE_LIMIT_DELAY = 2
    LOG_LEVEL = 'DEBUG'
    CACHE_TTL = {k: v // 10 for k, v in CACHE_TTL.items()}  # Cache plus court en dev