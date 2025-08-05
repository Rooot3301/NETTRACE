#!/usr/bin/env python3
"""
Analyseur de technologies web et sécurité
"""

import re
import ssl
import socket
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from config.settings import DEFAULT_HEADERS, REQUEST_TIMEOUT, TECHNOLOGY_SIGNATURES, SECURITY_HEADERS
from core.cache import cache
from utils import print_info, print_success, print_warning, print_error

class WebAnalyzer:
    """Analyseur de technologies web et sécurité"""
    
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.base_url = f"https://{domain}"
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
    
    def log_verbose(self, message: str):
        """Log en mode verbeux"""
        if self.verbose:
            from utils import print_info
            print_info(f"[WEB] {message}")
    
    def analyze_technologies(self) -> Dict:
        """Analyse les technologies utilisées"""
        cache_key = f"tech_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        self.log_verbose("Analyse des technologies web...")
        
        technologies = {
            'frameworks': [],
            'servers': [],
            'cdn': [],
            'analytics': [],
            'cms': [],
            'javascript_libraries': []
        }
        
        try:
            # Requête HTTP
            response = self.session.get(self.base_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            html_content = response.text.lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Analyse des headers
            self._analyze_headers(headers, technologies)
            
            # Analyse du contenu HTML
            self._analyze_html_content(html_content, technologies)
            
            # Analyse des scripts et CSS
            self._analyze_resources(response.text, technologies)
            
        except requests.RequestException as e:
            self.log_verbose(f"Erreur lors de l'analyse web: {str(e)}")
            technologies['error'] = str(e)
        
        cache.set(cache_key, technologies, 'http')
        return technologies
    
    def _analyze_headers(self, headers: Dict, technologies: Dict):
        """Analyse les headers HTTP"""
        # Serveur web
        server = headers.get('server', '')
        if server:
            for tech, signatures in TECHNOLOGY_SIGNATURES['servers'].items():
                if any(sig.lower() in server.lower() for sig in signatures):
                    if tech not in technologies['servers']:
                        technologies['servers'].append(tech)
        
        # CDN et services
        cdn_headers = ['cf-ray', 'x-served-by', 'x-cache', 'x-amz-cf-id']
        for header in cdn_headers:
            if header in headers:
                if 'cf-ray' in header:
                    technologies['cdn'].append('Cloudflare')
                elif 'x-amz' in header:
                    technologies['cdn'].append('AWS CloudFront')
                elif 'x-served-by' in header:
                    technologies['cdn'].append('Fastly')
    
    def _analyze_html_content(self, html: str, technologies: Dict):
        """Analyse le contenu HTML"""
        # Frameworks JavaScript
        for framework, signatures in TECHNOLOGY_SIGNATURES['frameworks'].items():
            if any(sig.lower() in html for sig in signatures):
                if framework not in technologies['frameworks']:
                    technologies['frameworks'].append(framework)
        
        # Analytics
        for analytics, signatures in TECHNOLOGY_SIGNATURES['analytics'].items():
            if any(sig.lower() in html for sig in signatures):
                if analytics not in technologies['analytics']:
                    technologies['analytics'].append(analytics)
        
        # CMS Detection
        cms_patterns = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Drupal': ['/sites/default/', 'drupal.js', 'drupal-'],
            'Joomla': ['/media/jui/', 'joomla', '/administrator/'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'Magento': ['magento', '/skin/frontend/']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern.lower() in html for pattern in patterns):
                if cms not in technologies['cms']:
                    technologies['cms'].append(cms)
    
    def _analyze_resources(self, html: str, technologies: Dict):
        """Analyse les ressources (JS, CSS)"""
        # Extraction des URLs de scripts
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        css_pattern = r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\']'
        
        scripts = re.findall(script_pattern, html, re.IGNORECASE)
        stylesheets = re.findall(css_pattern, html, re.IGNORECASE)
        
        # Analyse des bibliothèques JavaScript
        js_libraries = {
            'jQuery': ['jquery', 'jquery.min.js'],
            'Bootstrap': ['bootstrap.js', 'bootstrap.min.js'],
            'React': ['react.js', 'react.min.js'],
            'Angular': ['angular.js', 'angular.min.js'],
            'Vue.js': ['vue.js', 'vue.min.js']
        }
        
        all_resources = scripts + stylesheets
        for lib, patterns in js_libraries.items():
            if any(any(pattern in resource.lower() for pattern in patterns) for resource in all_resources):
                if lib not in technologies['javascript_libraries']:
                    technologies['javascript_libraries'].append(lib)
    
    def analyze_security_headers(self) -> Dict:
        """Analyse les headers de sécurité"""
        cache_key = f"security_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        self.log_verbose("Analyse des headers de sécurité...")
        
        security_analysis = {
            'headers': {},
            'score': 0,
            'max_score': sum(h['points'] for h in SECURITY_HEADERS.values()),
            'recommendations': []
        }
        
        try:
            response = self.session.get(self.base_url, timeout=REQUEST_TIMEOUT)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header_name, config in SECURITY_HEADERS.items():
                header_key = header_name.lower()
                
                if header_key in headers:
                    security_analysis['headers'][header_name] = {
                        'present': True,
                        'value': headers[header_key],
                        'points': config['points']
                    }
                    security_analysis['score'] += config['points']
                else:
                    security_analysis['headers'][header_name] = {
                        'present': False,
                        'value': None,
                        'points': 0
                    }
                    
                    if config['required']:
                        security_analysis['recommendations'].append(
                            f"Ajouter le header {header_name} pour améliorer la sécurité"
                        )
        
        except requests.RequestException as e:
            security_analysis['error'] = str(e)
        
        cache.set(cache_key, security_analysis, 'http')
        return security_analysis
    
    def analyze_ssl_certificate(self) -> Dict:
        """Analyse le certificat SSL"""
        cache_key = f"ssl_{self.domain}"
        cached = cache.get(cache_key, 'ssl')
        if cached:
            return cached
        
        self.log_verbose("Analyse du certificat SSL...")
        
        ssl_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'expiry_date': None,
            'san_domains': [],
            'protocol_version': None,
            'cipher_suite': None,
            'score': 0
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    ssl_info['expiry_date'] = cert['notAfter']
                    ssl_info['protocol_version'] = ssock.version()
                    ssl_info['cipher_suite'] = ssock.cipher()
                    
                    # SAN (Subject Alternative Names)
                    if 'subjectAltName' in cert:
                        ssl_info['san_domains'] = [name[1] for name in cert['subjectAltName']]
                    
                    # Calcul du score SSL
                    ssl_info['score'] = self._calculate_ssl_score(ssl_info)
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        cache.set(cache_key, ssl_info, 'ssl')
        return ssl_info
    
    def _calculate_ssl_score(self, ssl_info: Dict) -> int:
        """Calcule le score SSL"""
        score = 0
        
        # Certificat valide
        if ssl_info['valid']:
            score += 30
        
        # Protocole TLS moderne
        if ssl_info['protocol_version'] in ['TLSv1.2', 'TLSv1.3']:
            score += 25
        elif ssl_info['protocol_version'] == 'TLSv1.1':
            score += 15
        
        # Autorité de certification reconnue
        trusted_cas = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GlobalSign', 'GeoTrust']
        issuer_org = ssl_info.get('issuer', {}).get('organizationName', '')
        if any(ca.lower() in issuer_org.lower() for ca in trusted_cas):
            score += 20
        
        # SAN présent
        if ssl_info['san_domains']:
            score += 15
        
        # Vérification de l'expiration
        try:
            from datetime import datetime
            expiry = datetime.strptime(ssl_info['expiry_date'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry - datetime.now()).days
            
            if days_until_expiry > 30:
                score += 10
            elif days_until_expiry > 7:
                score += 5
        except:
            pass
        
        return min(score, 100)
    
    def check_common_files(self) -> Dict:
        """Vérifie la présence de fichiers communs"""
        cache_key = f"files_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        self.log_verbose("Vérification des fichiers communs...")
        
        common_files = {
            'robots.txt': '/robots.txt',
            'sitemap.xml': '/sitemap.xml',
            'security.txt': '/.well-known/security.txt',
            'humans.txt': '/humans.txt',
            'favicon.ico': '/favicon.ico'
        }
        
        file_status = {}
        
        for file_name, path in common_files.items():
            try:
                url = urljoin(self.base_url, path)
                response = self.session.head(url, timeout=5)
                
                file_status[file_name] = {
                    'exists': response.status_code == 200,
                    'status_code': response.status_code,
                    'size': response.headers.get('content-length'),
                    'content_type': response.headers.get('content-type')
                }
                
            except requests.RequestException:
                file_status[file_name] = {
                    'exists': False,
                    'status_code': None,
                    'error': 'Request failed'
                }
        
        cache.set(cache_key, file_status, 'http')
        return file_status
    
    def analyze_redirects(self) -> Dict:
        """Analyse les redirections HTTP/HTTPS"""
        self.log_verbose("Analyse des redirections...")
        
        redirect_info = {
            'http_to_https': False,
            'www_redirect': None,
            'redirect_chain': [],
            'final_url': None
        }
        
        # Test HTTP vers HTTPS
        try:
            http_url = f"http://{self.domain}"
            response = self.session.get(http_url, timeout=10, allow_redirects=True)
            
            redirect_info['redirect_chain'] = [r.url for r in response.history]
            redirect_info['final_url'] = response.url
            redirect_info['http_to_https'] = response.url.startswith('https://')
            
            # Vérification www
            if 'www.' in response.url:
                redirect_info['www_redirect'] = 'adds_www'
            elif 'www.' not in response.url and 'www.' in self.domain:
                redirect_info['www_redirect'] = 'removes_www'
            else:
                redirect_info['www_redirect'] = 'no_change'
                
        except requests.RequestException as e:
            redirect_info['error'] = str(e)
        
        return redirect_info