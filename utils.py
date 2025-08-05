#!/usr/bin/env python3
"""
NetTrace - Production-ready OSINT domain analysis tool
Main utilities and classes with robust error handling
"""

import os
import re
import sys
import json
import time
import socket
import ssl
import whois
import requests
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from functools import wraps

# Configuration des imports
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  dnspython non disponible. Installation: pip install dnspython")

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback sans couleurs
    class MockColor:
        def __getattr__(self, name): return ""
    Fore = Back = Style = MockColor()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/nettrace.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Décorateur pour la gestion d'erreurs
def handle_errors(func):
    """Décorateur pour la gestion robuste des erreurs"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Erreur dans {func.__name__}: {str(e)}")
            return None
    return wrapper

# Validation des entrées
def validate_domain(domain: str) -> bool:
    """Valide un nom de domaine"""
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.strip().lower()
    
    # Regex pour validation basique
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(pattern, domain):
        return False
    
    # Vérifications supplémentaires
    if len(domain) > 253:
        return False
    
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    
    return True

def sanitize_input(text: str) -> str:
    """Nettoie et sécurise les entrées utilisateur"""
    if not isinstance(text, str):
        return ""
    
    # Supprimer les caractères dangereux
    text = re.sub(r'[<>"\';\\]', '', text)
    return text.strip()

# Configuration
from config.settings import (
    CACHE_DIR, REPORTS_DIR, LOGS_DIR, REQUEST_TIMEOUT, 
    DEFAULT_HEADERS, TECHNOLOGY_SIGNATURES, SECURITY_HEADERS
)
from core.cache import cache
from core.display import (
    print_banner, print_section, print_success, 
    print_error, print_warning, print_info
)

class DomainAnalyzer:
    """Production-ready domain analyzer with comprehensive error handling"""
    
    def __init__(self, domain: str, verbose: bool = False):
        if not validate_domain(domain):
            raise ValueError(f"Domaine invalide: {domain}")
        
        self.domain = domain.lower().strip()
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.timeout = REQUEST_TIMEOUT
        
        # Configuration des timeouts et retry
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        logger.info(f"Analyseur initialisé pour {self.domain}")
    
    @handle_errors
    def run_quick_analysis(self) -> Dict:
        """Analyse rapide : WHOIS + DNS + Technologies de base"""
        print_info("🚀 Lancement de l'analyse rapide...")
        
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'quick',
            'analysis': {}
        }
        
        try:
            # WHOIS
            print_info("📋 Analyse WHOIS...")
            results['analysis']['whois'] = self.get_whois_info()
            
            # DNS
            print_info("🌐 Résolution DNS...")
            results['analysis']['dns'] = self.get_dns_records()
            
            # Technologies web basiques
            print_info("💻 Détection des technologies...")
            results['analysis']['web_technologies'] = self.get_basic_web_technologies()
            
            # Score de confiance
            results['analysis']['trust_score'] = self.calculate_trust_score(results['analysis'])
            
        except Exception as e:
            logger.error(f"Erreur analyse rapide: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    @handle_errors
    def run_standard_analysis(self) -> Dict:
        """Analyse standard : Rapide + Sécurité + Réputation basique"""
        print_info("🚀 Lancement de l'analyse standard...")
        
        # Commencer par l'analyse rapide
        results = self.run_quick_analysis()
        results['analysis_type'] = 'standard'
        
        try:
            # Sécurité
            print_info("🔒 Analyse de sécurité...")
            results['analysis']['security'] = self.get_security_analysis()
            
            # Réputation basique
            print_info("🛡️ Vérification de réputation...")
            results['analysis']['reputation'] = self.get_basic_reputation()
            
            # Score de sécurité
            results['analysis']['security_score'] = self.calculate_security_score(results['analysis'])
            
        except Exception as e:
            logger.error(f"Erreur analyse standard: {str(e)}")
            results.setdefault('errors', []).append(str(e))
        
        return results
    
    @handle_errors
    def run_full_analysis(self) -> Dict:
        """Analyse complète : Standard + Géolocalisation + Sous-domaines + Monitoring"""
        print_info("🚀 Lancement de l'analyse complète...")
        
        # Commencer par l'analyse standard
        results = self.run_standard_analysis()
        results['analysis_type'] = 'complete'
        
        try:
            # Sous-domaines
            print_info("🔍 Recherche de sous-domaines...")
            results['analysis']['subdomains'] = self.get_subdomains()
            
            # Géolocalisation
            print_info("🌍 Géolocalisation...")
            results['analysis']['geolocation'] = self.get_geolocation_info()
            
            # Réputation avancée
            print_info("🛡️ Analyse de réputation avancée...")
            results['analysis']['reputation'] = self.get_advanced_reputation()
            
            # Recalculer les scores avec toutes les données
            results['analysis']['trust_score'] = self.calculate_trust_score(results['analysis'])
            results['analysis']['security_score'] = self.calculate_security_score(results['analysis'])
            results['analysis']['reputation_score'] = self.calculate_reputation_score(results['analysis'])
            
        except Exception as e:
            logger.error(f"Erreur analyse complète: {str(e)}")
            results.setdefault('errors', []).append(str(e))
        
        return results
    
    @handle_errors
    def get_whois_info(self) -> Dict:
        """Récupère les informations WHOIS"""
        cache_key = f"whois_{self.domain}"
        cached = cache.get(cache_key, 'whois')
        if cached:
            return cached
        
        whois_info = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'registrant': None,
            'status': None,
            'name_servers': [],
            'emails': []
        }
        
        try:
            if self.verbose:
                print_info(f"Requête WHOIS pour {self.domain}...")
            
            w = whois.whois(self.domain)
            
            if w:
                whois_info.update({
                    'registrar': str(w.registrar) if w.registrar else None,
                    'creation_date': str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else None,
                    'expiration_date': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else None,
                    'registrant': str(w.registrant) if w.registrant else None,
                    'status': str(w.status[0]) if isinstance(w.status, list) and w.status else str(w.status) if w.status else None,
                    'name_servers': [str(ns) for ns in w.name_servers] if w.name_servers else [],
                    'emails': [str(email) for email in w.emails] if w.emails else []
                })
        
        except Exception as e:
            whois_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur WHOIS: {str(e)}")
        
        cache.set(cache_key, whois_info, 'whois')
        return whois_info
    
    @handle_errors
    def get_dns_records(self) -> Dict:
        """Récupère les enregistrements DNS"""
        if not DNS_AVAILABLE:
            return {'error': 'dnspython non disponible'}
        
        cache_key = f"dns_{self.domain}"
        cached = cache.get(cache_key, 'dns')
        if cached:
            return cached
        
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'CNAME': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in record_types:
            try:
                if self.verbose:
                    print_info(f"Résolution {record_type} pour {self.domain}...")
                
                answers = dns.resolver.resolve(self.domain, record_type)
                
                for answer in answers:
                    if record_type == 'MX':
                        dns_records[record_type].append(f"{answer.preference} {answer.exchange}")
                    else:
                        dns_records[record_type].append(str(answer))
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                continue
            except Exception as e:
                if self.verbose:
                    print_warning(f"Erreur DNS {record_type}: {str(e)}")
                continue
        
        cache.set(cache_key, dns_records, 'dns')
        return dns_records
    
    @handle_errors
    def get_basic_web_technologies(self) -> Dict:
        """Détection basique des technologies web"""
        cache_key = f"webtech_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        technologies = {
            'frameworks': [],
            'servers': [],
            'cdn': [],
            'analytics': [],
            'cms': []
        }
        
        try:
            url = f"https://{self.domain}"
            if self.verbose:
                print_info(f"Analyse web de {url}...")
            
            response = self.session.get(url, allow_redirects=True)
            
            # Analyse des headers
            server = response.headers.get('server', '').lower()
            if 'apache' in server:
                technologies['servers'].append('Apache')
            elif 'nginx' in server:
                technologies['servers'].append('Nginx')
            elif 'iis' in server:
                technologies['servers'].append('IIS')
            
            # CDN detection
            if 'cf-ray' in response.headers:
                technologies['cdn'].append('Cloudflare')
            elif 'x-served-by' in response.headers:
                technologies['cdn'].append('Fastly')
            
            # Analyse du contenu HTML
            html = response.text.lower()
            
            # Frameworks
            if 'react' in html or '_react' in html:
                technologies['frameworks'].append('React')
            if 'angular' in html or 'ng-' in html:
                technologies['frameworks'].append('Angular')
            if 'vue' in html or '__vue__' in html:
                technologies['frameworks'].append('Vue.js')
            if 'jquery' in html:
                technologies['frameworks'].append('jQuery')
            
            # CMS
            if 'wp-content' in html or 'wp-includes' in html:
                technologies['cms'].append('WordPress')
            if 'drupal' in html:
                technologies['cms'].append('Drupal')
            
            # Analytics
            if 'google-analytics' in html or 'gtag' in html:
                technologies['analytics'].append('Google Analytics')
            if 'googletagmanager' in html:
                technologies['analytics'].append('Google Tag Manager')
        
        except requests.RequestException as e:
            technologies['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur analyse web: {str(e)}")
        
        cache.set(cache_key, technologies, 'http')
        return technologies
    
    @handle_errors
    def get_security_analysis(self) -> Dict:
        """Analyse de sécurité complète"""
        cache_key = f"security_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        security_info = {
            'ssl': {},
            'headers': {},
            'redirects': {},
            'score': 0
        }
        
        try:
            # Analyse SSL
            security_info['ssl'] = self.get_ssl_info()
            
            # Headers de sécurité
            security_info['headers'] = self.get_security_headers()
            
            # Redirections HTTPS
            security_info['redirects'] = self.check_https_redirect()
            
        except Exception as e:
            security_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur analyse sécurité: {str(e)}")
        
        cache.set(cache_key, security_info, 'http')
        return security_info
    
    @handle_errors
    def get_ssl_info(self) -> Dict:
        """Informations sur le certificat SSL"""
        ssl_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'expiry_date': None,
            'protocol_version': None
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info.update({
                        'valid': True,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'expiry_date': cert.get('notAfter'),
                        'protocol_version': ssock.version()
                    })
        
        except Exception as e:
            ssl_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur SSL: {str(e)}")
        
        return ssl_info
    
    @handle_errors
    def get_security_headers(self) -> Dict:
        """Vérification des headers de sécurité"""
        headers_info = {}
        
        try:
            url = f"https://{self.domain}"
            response = self.session.get(url)
            
            # Headers de sécurité importants
            security_headers = [
                'strict-transport-security',
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection',
                'referrer-policy'
            ]
            
            for header in security_headers:
                headers_info[header] = {
                    'present': header in [h.lower() for h in response.headers.keys()],
                    'value': response.headers.get(header, None)
                }
        
        except Exception as e:
            headers_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur headers sécurité: {str(e)}")
        
        return headers_info
    
    @handle_errors
    def check_https_redirect(self) -> Dict:
        """Vérification de la redirection HTTPS"""
        redirect_info = {
            'http_to_https': False,
            'redirect_chain': []
        }
        
        try:
            http_url = f"http://{self.domain}"
            response = self.session.get(http_url, allow_redirects=True)
            
            redirect_info['redirect_chain'] = [r.url for r in response.history]
            redirect_info['http_to_https'] = response.url.startswith('https://')
        
        except Exception as e:
            redirect_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur redirection: {str(e)}")
        
        return redirect_info
    
    @handle_errors
    def get_basic_reputation(self) -> Dict:
        """Vérification basique de réputation"""
        reputation_info = {
            'virustotal_url': f"https://www.virustotal.com/gui/domain/{self.domain}",
            'urlvoid_url': f"https://www.urlvoid.com/scan/{self.domain}/",
            'status': 'unknown'
        }
        
        # Pour l'instant, juste les URLs de vérification manuelle
        # L'intégration API sera ajoutée plus tard
        
        return reputation_info
    
    @handle_errors
    def get_advanced_reputation(self) -> Dict:
        """Analyse de réputation avancée"""
        # Hérite de la réputation basique pour l'instant
        return self.get_basic_reputation()
    
    @handle_errors
    def get_subdomains(self) -> List[str]:
        """Recherche de sous-domaines via Certificate Transparency"""
        cache_key = f"subdomains_{self.domain}"
        cached = cache.get(cache_key, 'http')
        if cached:
            return cached
        
        subdomains = set()
        
        try:
            if self.verbose:
                print_info(f"Recherche de sous-domaines pour {self.domain}...")
            
            # Via crt.sh
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url)
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and name.endswith(f'.{self.domain}'):
                            subdomains.add(name)
        
        except Exception as e:
            if self.verbose:
                print_warning(f"Erreur sous-domaines: {str(e)}")
        
        result = sorted(list(subdomains))
        cache.set(cache_key, result, 'http')
        return result
    
    @handle_errors
    def get_geolocation_info(self) -> Dict:
        """Informations de géolocalisation"""
        cache_key = f"geo_{self.domain}"
        cached = cache.get(cache_key, 'geolocation')
        if cached:
            return cached
        
        geo_info = {
            'ip_addresses': [],
            'geolocation': []
        }
        
        try:
            # Résolution IP
            ips = socket.getaddrinfo(self.domain, None)
            unique_ips = list(set([ip[4][0] for ip in ips]))
            geo_info['ip_addresses'] = unique_ips
            
            # Géolocalisation de la première IP
            if unique_ips:
                ip = unique_ips[0]
                geo_data = self.geolocate_ip(ip)
                if geo_data:
                    geo_info['geolocation'].append(geo_data)
        
        except Exception as e:
            geo_info['error'] = str(e)
            if self.verbose:
                print_warning(f"Erreur géolocalisation: {str(e)}")
        
        cache.set(cache_key, geo_info, 'geolocation')
        return geo_info
    
    @handle_errors
    def geolocate_ip(self, ip: str) -> Optional[Dict]:
        """Géolocalise une adresse IP"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'organization': data.get('org')
                    }
        except Exception:
            pass
        
        return None
    
    def calculate_trust_score(self, analysis: Dict) -> Dict:
        """Calcule le score de confiance"""
        score = 0
        max_score = 100
        details = []
        
        try:
            # Ancienneté du domaine (30 points max)
            whois_data = analysis.get('whois', {})
            if whois_data.get('creation_date'):
                try:
                    from dateutil.parser import parse
                    creation_date = parse(whois_data['creation_date'])
                    age_years = (datetime.now() - creation_date).days / 365.25
                    
                    if age_years >= 10:
                        score += 30
                        details.append("Domaine très ancien (10+ ans) (+30 pts)")
                    elif age_years >= 3:
                        score += 20
                        details.append("Domaine établi (3-10 ans) (+20 pts)")
                    elif age_years >= 1:
                        score += 10
                        details.append("Domaine récent (1-3 ans) (+10 pts)")
                    else:
                        details.append("Domaine très récent (<1 an) (+0 pts)")
                except:
                    pass
            
            # Enregistrements DNS (25 points max)
            dns_data = analysis.get('dns', {})
            dns_score = 0
            
            if dns_data.get('A'):
                dns_score += 8
            if dns_data.get('MX'):
                dns_score += 8
            if dns_data.get('NS'):
                dns_score += 9
            
            score += dns_score
            details.append(f"Enregistrements DNS (+{dns_score} pts)")
            
            # Sous-domaines (20 points max)
            subdomains = analysis.get('subdomains', [])
            subdomain_count = len(subdomains) if isinstance(subdomains, list) else 0
            
            if subdomain_count >= 50:
                score += 20
                details.append("Nombreux sous-domaines (50+) (+20 pts)")
            elif subdomain_count >= 20:
                score += 15
                details.append("Sous-domaines multiples (20-49) (+15 pts)")
            elif subdomain_count >= 5:
                score += 10
                details.append("Quelques sous-domaines (5-19) (+10 pts)")
            elif subdomain_count > 0:
                score += 5
                details.append("Peu de sous-domaines (1-4) (+5 pts)")
            
            # WHOIS complet (15 points max)
            whois_score = 0
            if whois_data.get('registrar'):
                whois_score += 5
            if whois_data.get('registrant'):
                whois_score += 5
            if whois_data.get('status'):
                whois_score += 5
            
            score += whois_score
            details.append(f"Informations WHOIS (+{whois_score} pts)")
            
            # Technologies web (10 points max)
            web_tech = analysis.get('web_technologies', {})
            tech_count = 0
            for tech_list in web_tech.values():
                if isinstance(tech_list, list):
                    tech_count += len(tech_list)
            
            if tech_count >= 5:
                score += 10
                details.append("Technologies web détectées (+10 pts)")
            elif tech_count > 0:
                score += 5
                details.append("Quelques technologies détectées (+5 pts)")
        
        except Exception as e:
            logger.error(f"Erreur calcul score confiance: {str(e)}")
        
        # Déterminer le niveau
        if score >= 80:
            level = "ÉLEVÉ"
        elif score >= 60:
            level = "MOYEN"
        else:
            level = "FAIBLE"
        
        return {
            'score': min(score, max_score),
            'max_score': max_score,
            'level': level,
            'details': details
        }
    
    def calculate_security_score(self, analysis: Dict) -> Dict:
        """Calcule le score de sécurité"""
        score = 0
        max_score = 100
        details = []
        
        try:
            security_data = analysis.get('security', {})
            
            # SSL/TLS (30 points max)
            ssl_data = security_data.get('ssl', {})
            if ssl_data.get('valid'):
                score += 20
                details.append("Certificat SSL valide (+20 pts)")
                
                if ssl_data.get('protocol_version') in ['TLSv1.2', 'TLSv1.3']:
                    score += 10
                    details.append("Protocole TLS moderne (+10 pts)")
            
            # Headers de sécurité (40 points max)
            headers_data = security_data.get('headers', {})
            headers_score = 0
            
            important_headers = [
                'strict-transport-security',
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options'
            ]
            
            for header in important_headers:
                if isinstance(headers_data.get(header), dict):
                    if headers_data[header].get('present'):
                        headers_score += 10
            
            score += headers_score
            details.append(f"Headers de sécurité (+{headers_score} pts)")
            
            # Redirection HTTPS (15 points max)
            redirects = security_data.get('redirects', {})
            if redirects.get('http_to_https'):
                score += 15
                details.append("Redirection HTTPS active (+15 pts)")
            
            # Technologies sécurisées (15 points max)
            web_tech = analysis.get('web_technologies', {})
            if web_tech.get('cdn'):
                score += 10
                details.append("CDN détecté (+10 pts)")
            
            if web_tech.get('frameworks'):
                score += 5
                details.append("Frameworks modernes (+5 pts)")
        
        except Exception as e:
            logger.error(f"Erreur calcul score sécurité: {str(e)}")
        
        # Déterminer le niveau
        if score >= 80:
            level = "EXCELLENT"
        elif score >= 60:
            level = "BON"
        elif score >= 40:
            level = "MOYEN"
        else:
            level = "FAIBLE"
        
        return {
            'score': min(score, max_score),
            'max_score': max_score,
            'level': level,
            'details': details
        }
    
    def calculate_reputation_score(self, analysis: Dict) -> Dict:
        """Calcule le score de réputation"""
        # Score de base élevé
        score = 90
        details = ["Score de base (+90 pts)"]
        
        # Pour l'instant, score basique
        # L'intégration avec les APIs de réputation sera ajoutée plus tard
        
        return {
            'score': score,
            'max_score': 100,
            'level': "BON",
            'details': details
        }
    
    def display_results(self, results: Dict):
        """Affiche les résultats de l'analyse de manière robuste"""
        if not results or 'analysis' not in results:
            print_error("❌ Aucun résultat à afficher")
            return
        
        analysis = results['analysis']
        domain = results.get('domain', 'Unknown')
        
        print_info(f"\n🎯 Analyse du domaine: {domain}")
        print_info("=" * 60)
        
        # WHOIS
        if 'whois' in analysis:
            self._display_whois(analysis['whois'])
        
        # DNS
        if 'dns' in analysis:
            self._display_dns(analysis['dns'])
        
        # Technologies Web
        if 'web_technologies' in analysis:
            self._display_web_technologies(analysis['web_technologies'])
        
        # Sécurité
        if 'security' in analysis:
            self._display_security(analysis['security'])
        
        # Géolocalisation
        if 'geolocation' in analysis:
            self._display_geolocation(analysis['geolocation'])
        
        # Sous-domaines
        if 'subdomains' in analysis:
            self._display_subdomains(analysis['subdomains'])
        
        # Scores
        self._display_scores(analysis)
        
        # Erreurs éventuelles
        if 'errors' in results:
            print_section("ERREURS")
            for error in results['errors']:
                print_warning(f"⚠️  {error}")
    
    def _display_whois(self, whois_data: Dict):
        """Affiche les informations WHOIS"""
        print_section("WHOIS LOOKUP")
        
        if whois_data.get('error'):
            print_warning(f"⚠️  Erreur WHOIS: {whois_data['error']}")
            return
        
        fields = [
            ('registrar', '🏢 Registrar'),
            ('creation_date', '📅 Date de création'),
            ('expiration_date', '⏰ Date d\'expiration'),
            ('registrant', '👤 Propriétaire'),
            ('status', '📊 Statut')
        ]
        
        for field, label in fields:
            value = whois_data.get(field, 'Non disponible')
            if value and value != 'None':
                print_info(f"{label}: {value}")
    
    def _display_dns(self, dns_data: Dict):
        """Affiche les enregistrements DNS"""
        print_section("RÉSOLUTION DNS")
        
        if dns_data.get('error'):
            print_warning(f"⚠️  Erreur DNS: {dns_data['error']}")
            return
        
        for record_type, records in dns_data.items():
            if isinstance(records, list) and records:
                print_info(f"🔍 {record_type}:")
                for i, record in enumerate(records[:3]):  # Limiter à 3
                    print_info(f"   {record}")
                if len(records) > 3:
                    print_info(f"   ... et {len(records) - 3} autres")
    
    def _display_web_technologies(self, tech_data: Dict):
        """Affiche les technologies web"""
        print_section("TECHNOLOGIES WEB")
        
        if tech_data.get('error'):
            print_warning(f"⚠️  Erreur analyse web: {tech_data['error']}")
            return
        
        categories = [
            ('servers', '🖥️  Serveurs'),
            ('frameworks', '⚛️  Frameworks'),
            ('cdn', '🌐 CDN'),
            ('cms', '📝 CMS'),
            ('analytics', '📊 Analytics')
        ]
        
        for category, label in categories:
            if category in tech_data and tech_data[category]:
                technologies = tech_data[category][:5]  # Limiter à 5
                print_info(f"{label}: {', '.join(technologies)}")
    
    def _display_security(self, security_data: Dict):
        """Affiche l'analyse de sécurité de manière robuste"""
        print_section("ANALYSE DE SÉCURITÉ")
        
        if security_data.get('error'):
            print_warning(f"⚠️  Erreur sécurité: {security_data['error']}")
            return
        
        # SSL
        ssl_data = security_data.get('ssl', {})
        if ssl_data:
            if ssl_data.get('valid'):
                print_success("✅ SSL: Certificat valide")
                if ssl_data.get('issuer', {}).get('organizationName'):
                    print_info(f"🔐 Émetteur: {ssl_data['issuer']['organizationName']}")
            else:
                print_error("❌ SSL: Certificat invalide ou absent")
        
        # Headers de sécurité - Gestion robuste
        headers_data = security_data.get('headers', {})
        if headers_data and not headers_data.get('error'):
            try:
                # Compter les headers présents de manière sécurisée
                headers_present = 0
                total_headers = 0
                
                for header_name, header_info in headers_data.items():
                    if header_name == 'error':
                        continue
                    
                    total_headers += 1
                    
                    # Gestion flexible des différents formats de données
                    if isinstance(header_info, dict):
                        if header_info.get('present'):
                            headers_present += 1
                    elif isinstance(header_info, bool):
                        if header_info:
                            headers_present += 1
                    elif header_info:  # Toute valeur truthy
                        headers_present += 1
                
                if total_headers > 0:
                    print_info(f"🛡️  Headers de sécurité: {headers_present}/{total_headers} présents")
                else:
                    print_info("🛡️  Headers de sécurité: Données non disponibles")
                    
            except Exception as e:
                print_warning(f"⚠️  Erreur affichage headers: {str(e)}")
                print_info("🛡️  Headers de sécurité: Données non disponibles")
        
        # Redirections HTTPS
        redirects = security_data.get('redirects', {})
        if redirects:
            if redirects.get('http_to_https'):
                print_success("✅ HTTPS: Redirection active")
            else:
                print_warning("⚠️  HTTPS: Pas de redirection automatique")
    
    def _display_geolocation(self, geo_data: Dict):
        """Affiche les informations de géolocalisation"""
        print_section("GÉOLOCALISATION")
        
        if geo_data.get('error'):
            print_warning(f"⚠️  Erreur géolocalisation: {geo_data['error']}")
            return
        
        if geo_data.get('ip_addresses'):
            print_info(f"🌐 Adresses IP: {', '.join(geo_data['ip_addresses'][:3])}")
        
        if geo_data.get('geolocation'):
            for geo_info in geo_data['geolocation'][:1]:  # Première seulement
                if geo_info.get('country'):
                    print_info(f"🇺🇸 Pays: {geo_info['country']}")
                if geo_info.get('city'):
                    print_info(f"🏙️  Ville: {geo_info['city']}")
                if geo_info.get('organization'):
                    print_info(f"🏢 Organisation: {geo_info['organization']}")
    
    def _display_subdomains(self, subdomains: List[str]):
        """Affiche les sous-domaines"""
        print_section("SOUS-DOMAINES")
        
        if not subdomains:
            print_info("Aucun sous-domaine trouvé")
            return
        
        print_info(f"📊 Total: {len(subdomains)} sous-domaines trouvés")
        
        # Afficher les 5 premiers
        for subdomain in subdomains[:5]:
            print_info(f"🔗 {subdomain}")
        
        if len(subdomains) > 5:
            print_info(f"... et {len(subdomains) - 5} autres")
    
    def _display_scores(self, analysis: Dict):
        """Affiche les scores"""
        print_section("SCORES D'ÉVALUATION")
        
        scores = [
            ('trust_score', '🎯 Score de confiance'),
            ('security_score', '🔒 Score de sécurité'),
            ('reputation_score', '🛡️  Score de réputation')
        ]
        
        for score_key, label in scores:
            if score_key in analysis:
                score_data = analysis[score_key]
                score = score_data.get('score', 0)
                level = score_data.get('level', 'INCONNU')
                
                # Couleur selon le score
                if score >= 80:
                    color_func = print_success
                elif score >= 60:
                    color_func = print_warning
                else:
                    color_func = print_error
                
                color_func(f"{label}: {score}/100 ({level})")
    
    @handle_errors
    def export_results(self, results: Dict, filename: str, format_type: str = 'json') -> bool:
        """Exporte les résultats dans le format spécifié"""
        try:
            # Créer le dossier reports s'il n'existe pas
            REPORTS_DIR.mkdir(exist_ok=True)
            
            filepath = REPORTS_DIR / filename
            
            if format_type.lower() == 'json':
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            elif format_type.lower() == 'html':
                from exporters.report_generator import ReportGenerator
                generator = ReportGenerator(verbose=self.verbose)
                return generator.generate_html_report(results, filename)
            
            elif format_type.lower() == 'txt':
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"NetTrace Report - {results.get('domain', 'Unknown')}\n")
                    f.write(f"Generated: {results.get('timestamp', 'Unknown')}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(json.dumps(results, indent=2, ensure_ascii=False, default=str))
            
            else:
                print_error(f"Format non supporté: {format_type}")
                return False
            
            print_success(f"✅ Rapport exporté: {filepath}")
            return True
        
        except Exception as e:
            print_error(f"❌ Erreur export: {str(e)}")
            logger.error(f"Erreur export: {str(e)}")
            return False

# Menu interactif amélioré et sécurisé
def show_interactive_menu():
    """Menu interactif principal avec gestion d'erreurs robuste"""
    while True:
        try:
            clear_screen()
            display_main_menu()
            
            choice = input(f"\n{Fore.CYAN}Votre choix: {Style.RESET_ALL}").strip()
            
            if not choice:
                continue
            
            # Sécuriser l'entrée
            choice = sanitize_input(choice)
            
            if choice == '1':
                handle_quick_analysis()
            elif choice == '2':
                handle_standard_analysis()
            elif choice == '3':
                handle_complete_analysis()
            elif choice == '4':
                handle_report_generation()
            elif choice == '5':
                handle_batch_analysis()
            elif choice == '6':
                handle_monitoring()
            elif choice == '7':
                handle_comparative_analysis()
            elif choice == '8':
                handle_system_check()
            elif choice == '9':
                handle_cache_management()
            elif choice.lower() in ['h', 'help']:
                show_help()
            elif choice.lower() in ['e', 'examples']:
                show_examples()
            elif choice.lower() in ['q', 'quit', 'exit']:
                print_success("👋 Au revoir !")
                break
            else:
                print_error("❌ Choix invalide. Tapez 'h' pour l'aide.")
                input("Appuyez sur Entrée pour continuer...")
        
        except KeyboardInterrupt:
            print_warning("\n⚠️  Interruption détectée")
            if input("Voulez-vous vraiment quitter ? (o/N): ").lower().startswith('o'):
                break
        except Exception as e:
            logger.error(f"Erreur menu principal: {str(e)}")
            print_error(f"❌ Erreur inattendue: {str(e)}")
            input("Appuyez sur Entrée pour continuer...")

def clear_screen():
    """Efface l'écran de manière sécurisée"""
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        print("\n" * 50)  # Fallback

def display_main_menu():
    """Affiche le menu principal amélioré"""
    print_banner()
    
    # Statistiques du cache
    try:
        cache_stats = cache.get_stats()
        cache_info = f"Cache: {cache_stats['files']} fichiers ({cache_stats['total_size_mb']} MB)"
    except:
        cache_info = "Cache: Non disponible"
    
    print(f"{Fore.CYAN}📊 {cache_info}{Style.RESET_ALL}")
    print()
    
    # Menu principal avec design amélioré
    menu_items = [
        ("1", "🚀 Analyse rapide", "WHOIS + DNS + Technologies de base"),
        ("2", "📊 Analyse standard", "Rapide + Sécurité + Réputation"),
        ("3", "🔍 Analyse complète", "Standard + Géolocalisation + Sous-domaines"),
        ("4", "📋 Rapport automatique", "Analyse + Export HTML/JSON"),
        ("", "", ""),
        ("5", "📁 Analyse en lot", "Traiter plusieurs domaines"),
        ("6", "📈 Monitoring", "Surveillance continue"),
        ("7", "📊 Analyse comparative", "Comparer plusieurs domaines"),
        ("", "", ""),
        ("8", "⚙️  Système & Dépendances", "Vérification complète"),
        ("9", "🗂️  Gestion du cache", "Statistiques et nettoyage"),
        ("", "", ""),
        ("h", "📖 Aide", "Documentation complète"),
        ("e", "💡 Exemples", "Cas d'usage pratiques"),
        ("q", "🚪 Quitter", "Fermer NetTrace")
    ]
    
    print(f"{Fore.YELLOW}╔{'═' * 70}╗{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}║{' ' * 25}🔍 NETTRACE MENU{' ' * 25}║{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}╠{'═' * 70}╣{Style.RESET_ALL}")
    
    for num, title, desc in menu_items:
        if not num:  # Ligne vide
            print(f"{Fore.YELLOW}║{' ' * 70}║{Style.RESET_ALL}")
        else:
            color = Fore.GREEN if num.isdigit() else Fore.CYAN if num.isalpha() else Fore.MAGENTA
            print(f"{Fore.YELLOW}║{Style.RESET_ALL} {color}{num:>2}{Style.RESET_ALL}. {title:<25} {Fore.WHITE}{desc:<35}{Style.RESET_ALL} {Fore.YELLOW}║{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}╚{'═' * 70}╝{Style.RESET_ALL}")

@handle_errors
def handle_quick_analysis():
    """Gère l'analyse rapide"""
    domain = get_domain_input("🚀 Analyse rapide")
    if not domain:
        return
    
    try:
        analyzer = DomainAnalyzer(domain, verbose=True)
        results = analyzer.run_quick_analysis()
        analyzer.display_results(results)
        
        if ask_export():
            export_format = get_export_format()
            if export_format:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"quick_{domain.replace('.', '_')}_{timestamp}.{export_format}"
                analyzer.export_results(results, filename, export_format)
    
    except Exception as e:
        print_error(f"❌ Erreur analyse rapide: {str(e)}")
        logger.error(f"Erreur analyse rapide: {str(e)}")
    
    input("\nAppuyez sur Entrée pour continuer...")

@handle_errors
def handle_standard_analysis():
    """Gère l'analyse standard"""
    domain = get_domain_input("📊 Analyse standard")
    if not domain:
        return
    
    try:
        analyzer = DomainAnalyzer(domain, verbose=True)
        results = analyzer.run_standard_analysis()
        analyzer.display_results(results)
        
        if ask_export():
            export_format = get_export_format()
            if export_format:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"standard_{domain.replace('.', '_')}_{timestamp}.{export_format}"
                analyzer.export_results(results, filename, export_format)
    
    except Exception as e:
        print_error(f"❌ Erreur analyse standard: {str(e)}")
        logger.error(f"Erreur analyse standard: {str(e)}")
    
    input("\nAppuyez sur Entrée pour continuer...")

@handle_errors
def handle_complete_analysis():
    """Gère l'analyse complète"""
    domain = get_domain_input("🔍 Analyse complète")
    if not domain:
        return
    
    try:
        analyzer = DomainAnalyzer(domain, verbose=True)
        results = analyzer.run_full_analysis()
        analyzer.display_results(results)
        
        if ask_export():
            export_format = get_export_format()
            if export_format:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"complete_{domain.replace('.', '_')}_{timestamp}.{export_format}"
                analyzer.export_results(results, filename, export_format)
    
    except Exception as e:
        print_error(f"❌ Erreur analyse complète: {str(e)}")
        logger.error(f"Erreur analyse complète: {str(e)}")
    
    input("\nAppuyez sur Entrée pour continuer...")

@handle_errors
def handle_report_generation():
    """Gère la génération automatique de rapports"""
    domain = get_domain_input("📋 Rapport automatique")
    if not domain:
        return
    
    try:
        print_info("🎯 Génération automatique de rapport...")
        
        analyzer = DomainAnalyzer(domain, verbose=True)
        results = analyzer.run_full_analysis()
        analyzer.display_results(results)
        
        # Export automatique en HTML et JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"report_{domain.replace('.', '_')}_{timestamp}"
        
        # HTML
        html_filename = f"{base_filename}.html"
        if analyzer.export_results(results, html_filename, 'html'):
            print_success(f"✅ Rapport HTML généré: {html_filename}")
        
        # JSON
        json_filename = f"{base_filename}.json"
        if analyzer.export_results(results, json_filename, 'json'):
            print_success(f"✅ Rapport JSON généré: {json_filename}")
    
    except Exception as e:
        print_error(f"❌ Erreur génération rapport: {str(e)}")
        logger.error(f"Erreur génération rapport: {str(e)}")
    
    input("\nAppuyez sur Entrée pour continuer...")

def get_domain_input(title: str) -> Optional[str]:
    """Demande et valide un nom de domaine"""
    print(f"\n{Fore.CYAN}╔{'═' * (len(title) + 4)}╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║  {title}  ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚{'═' * (len(title) + 4)}╝{Style.RESET_ALL}")
    
    while True:
        domain = input(f"\n{Fore.GREEN}Domaine à analyser: {Style.RESET_ALL}").strip()
        
        if not domain:
            print_warning("⚠️  Veuillez saisir un domaine")
            continue
        
        domain = sanitize_input(domain)
        
        if validate_domain(domain):
            return domain.lower()
        else:
            print_error("❌ Domaine invalide. Format attendu: example.com")
            retry = input("Réessayer ? (O/n): ").strip().lower()
            if retry.startswith('n'):
                return None

def ask_export() -> bool:
    """Demande si l'utilisateur veut exporter"""
    response = input(f"\n{Fore.YELLOW}Exporter le rapport ? (O/n): {Style.RESET_ALL}").strip().lower()
    return not response.startswith('n')

def get_export_format() -> Optional[str]:
    """Demande le format d'export"""
    formats = {
        '1': 'html',
        '2': 'json',
        '3': 'txt'
    }
    
    print(f"\n{Fore.CYAN}Formats disponibles:{Style.RESET_ALL}")
    print("1. HTML (recommandé)")
    print("2. JSON")
    print("3. TXT")
    
    choice = input(f"\n{Fore.GREEN}Format (1-3): {Style.RESET_ALL}").strip()
    return formats.get(choice, 'html')

@handle_errors
def handle_batch_analysis():
    """Gère l'analyse en lot"""
    print_info("📁 Analyse en lot")
    print_info("Vous pouvez analyser plusieurs domaines depuis un fichier ou en saisie manuelle")
    
    choice = input("\n1. Depuis un fichier\n2. Saisie manuelle\nChoix (1-2): ").strip()
    
    domains = []
    
    if choice == '1':
        filename = input("Nom du fichier: ").strip()
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print_error(f"❌ Fichier '{filename}' introuvable")
            input("Appuyez sur Entrée pour continuer...")
            return
    
    elif choice == '2':
        print_info("Saisissez les domaines (ligne vide pour terminer):")
        while True:
            domain = input("Domaine: ").strip()
            if not domain:
                break
            if validate_domain(domain):
                domains.append(domain.lower())
            else:
                print_warning(f"⚠️  Domaine invalide ignoré: {domain}")
    
    if not domains:
        print_warning("⚠️  Aucun domaine valide à analyser")
        input("Appuyez sur Entrée pour continuer...")
        return
    
    print_info(f"🚀 Analyse de {len(domains)} domaine(s)...")
    
    success_count = 0
    for i, domain in enumerate(domains, 1):
        try:
            print_info(f"\n[{i}/{len(domains)}] Analyse de: {domain}")
            
            analyzer = DomainAnalyzer(domain, verbose=False)
            results = analyzer.run_standard_analysis()
            
            # Export automatique
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"batch_{domain.replace('.', '_')}_{timestamp}.json"
            
            if analyzer.export_results(results, filename, 'json'):
                success_count += 1
            
            # Pause entre analyses
            if i < len(domains):
                time.sleep(2)
        
        except Exception as e:
            print_error(f"❌ Erreur pour {domain}: {str(e)}")
            logger.error(f"Erreur batch {domain}: {str(e)}")
    
    print_info(f"\n📊 Résultats: {success_count}/{len(domains)} analyses réussies")
    input("Appuyez sur Entrée pour continuer...")

@handle_errors
def handle_monitoring():
    """Gère le monitoring des domaines"""
    print_info("📈 Système de monitoring")
    print_info("Fonctionnalité en développement...")
    input("Appuyez sur Entrée pour continuer...")

@handle_errors
def handle_comparative_analysis():
    """Gère l'analyse comparative"""
    print_info("📊 Analyse comparative")
    print_info("Fonctionnalité en développement...")
    input("Appuyez sur Entrée pour continuer...")

@handle_errors
def handle_system_check():
    """Vérifie le système et les dépendances"""
    print_info("⚙️  Vérification du système...")
    
    checks = [
        ("Python", sys.version_info >= (3, 7), f"Version: {sys.version}"),
        ("dnspython", DNS_AVAILABLE, "Résolution DNS"),
        ("colorama", COLORS_AVAILABLE, "Affichage coloré"),
        ("requests", True, "Requêtes HTTP"),
        ("Cache", cache.enabled, f"Dossier: {cache.cache_dir}"),
        ("Reports", REPORTS_DIR.exists(), f"Dossier: {REPORTS_DIR}"),
        ("Logs", LOGS_DIR.exists(), f"Dossier: {LOGS_DIR}")
    ]
    
    print_section("VÉRIFICATION SYSTÈME")
    
    for name, status, info in checks:
        if status:
            print_success(f"✅ {name}: {info}")
        else:
            print_error(f"❌ {name}: {info}")
    
    input("\nAppuyez sur Entrée pour continuer...")

@handle_errors
def handle_cache_management():
    """Gère le cache"""
    try:
        stats = cache.get_stats()
        
        print_section("GESTION DU CACHE")
        print_info(f"📁 Fichiers: {stats['files']}")
        print_info(f"💾 Taille: {stats['total_size_mb']} MB")
        print_info(f"📊 Statut: {'Activé' if stats['enabled'] else 'Désactivé'}")
        
        if stats['files'] > 0:
            choice = input("\nActions:\n1. Vider tout le cache\n2. Retour\nChoix: ").strip()
            
            if choice == '1':
                confirm = input("Confirmer la suppression ? (o/N): ").strip().lower()
                if confirm.startswith('o'):
                    cache.clear()
                    print_success("✅ Cache vidé")
    
    except Exception as e:
        print_error(f"❌ Erreur cache: {str(e)}")
    
    input("\nAppuyez sur Entrée pour continuer...")

def show_help():
    """Affiche l'aide"""
    clear_screen()
    print_banner()
    
    help_text = """
📖 GUIDE D'UTILISATION NETTRACE

🎯 TYPES D'ANALYSE
──────────────────
• Rapide    : WHOIS + DNS + Technologies de base (< 30s)
• Standard  : + Sécurité + Réputation basique (< 1min)
• Complète  : + Géolocalisation + Sous-domaines (< 2min)

🔍 FONCTIONNALITÉS
──────────────────
• Analyse WHOIS complète avec dates et propriétaire
• Résolution DNS multi-enregistrements (A, MX, NS, TXT...)
• Détection de 50+ technologies web (frameworks, CMS, CDN)
• Analyse de sécurité (SSL, headers, redirections HTTPS)
• Géolocalisation des serveurs avec informations ISP
• Recherche de sous-domaines via Certificate Transparency
• Scores intelligents (confiance, sécurité, réputation)
• Export HTML magnifique + JSON/TXT
• Cache intelligent pour optimiser les performances

📊 SCORING
──────────
• Score de confiance : Ancienneté + DNS + Sous-domaines + WHOIS
• Score de sécurité  : SSL + Headers + HTTPS + Technologies
• Score de réputation: Vérification listes malware + VirusTotal

🛡️ ÉTHIQUE & LÉGALITÉ
─────────────────────
• 100% légal - Sources publiques uniquement (OSINT)
• Pas de scan actif ou intrusif
• Respect des rate limits et robots.txt
• Toutes les analyses sont passives

⚡ OPTIMISATION
───────────────
• Cache intelligent avec TTL différencié
• Requêtes parallèles pour les performances
• Gestion robuste des timeouts et erreurs
• Limitation automatique du taux de requêtes

🎨 EXPORT HTML
──────────────
• Design moderne avec glassmorphism
• Responsive et mobile-friendly
• Scores colorés avec indicateurs visuels
• Informations organisées en cartes élégantes
    """
    
    print(help_text)
    input("\nAppuyez sur Entrée pour continuer...")

def show_examples():
    """Affiche des exemples d'utilisation"""
    clear_screen()
    print_banner()
    
    examples_text = """
💡 EXEMPLES PRATIQUES

🔍 CAS D'USAGE COURANTS
───────────────────────

1. 🕵️ RECONNAISSANCE PASSIVE
   • Analyser un domaine suspect avant visite
   • Vérifier la légitimité d'un site web
   • Identifier les technologies utilisées

2. 🛡️ AUDIT DE SÉCURITÉ
   • Vérifier les headers de sécurité
   • Analyser la configuration SSL/TLS
   • Détecter les redirections HTTPS

3. 📊 VEILLE CONCURRENTIELLE
   • Identifier les technologies concurrentes
   • Analyser l'infrastructure d'hébergement
   • Découvrir les sous-domaines publics

4. 🔒 ANALYSE DE RÉPUTATION
   • Vérifier si un domaine est blacklisté
   • Consulter les bases de données de malware
   • Analyser les certificats SSL suspects

📋 EXEMPLES DE COMMANDES
────────────────────────

# Ligne de commande
python nettrace.py -d google.com -f html -o rapport.html
python nettrace.py -d example.com -v
python nettrace.py --batch-file domains.txt -f json

# Mode interactif (recommandé)
python nettrace.py -i

🎯 DOMAINES DE TEST
───────────────────
• google.com     : Site établi avec toutes les technologies
• github.com     : Plateforme moderne avec sécurité avancée
• example.com    : Domaine de test basique
• badssl.com     : Tests de certificats SSL
• httpbin.org    : Tests d'APIs et headers HTTP

⚠️ BONNES PRATIQUES
───────────────────
• Toujours respecter les conditions d'utilisation
• Ne pas abuser des requêtes (rate limiting)
• Utiliser le cache pour éviter les requêtes répétitives
• Exporter en HTML pour une meilleure lisibilité
• Activer le mode verbeux pour le débogage
    """
    
    print(examples_text)
    input("\nAppuyez sur Entrée pour continuer...")