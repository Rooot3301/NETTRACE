#!/usr/bin/env python3
"""
Analyseur de réputation et sécurité
"""

import requests
import hashlib
from typing import Dict, List, Optional
from urllib.parse import quote

from config.settings import API_KEYS, REQUEST_TIMEOUT
from core.cache import cache
from utils import print_info, print_warning, print_error

class ReputationAnalyzer:
    """Analyseur de réputation"""
    
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
    
    def log_verbose(self, message: str):
        """Log en mode verbeux"""
        if self.verbose:
            print_info(f"[REP] {message}")
    
    def check_virustotal(self) -> Dict:
        """Vérification VirusTotal"""
        cache_key = f"vt_{self.domain}"
        cached = cache.get(cache_key, 'reputation')
        if cached:
            return cached
        
        self.log_verbose("Vérification VirusTotal...")
        
        vt_info = {
            'url': f"https://www.virustotal.com/gui/domain/{self.domain}",
            'api_available': bool(API_KEYS.get('virustotal')),
            'scan_results': None
        }
        
        if API_KEYS.get('virustotal'):
            try:
                headers = {'x-apikey': API_KEYS['virustotal']}
                url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
                
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    vt_info['scan_results'] = {
                        'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                        'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                        'clean': attributes.get('last_analysis_stats', {}).get('clean', 0),
                        'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                        'reputation': attributes.get('reputation', 0),
                        'categories': attributes.get('categories', {}),
                        'last_analysis_date': attributes.get('last_analysis_date')
                    }
                else:
                    vt_info['error'] = f"API Error: {response.status_code}"
                    
            except Exception as e:
                vt_info['error'] = str(e)
        
        cache.set(cache_key, vt_info, 'reputation')
        return vt_info
    
    def check_urlvoid(self) -> Dict:
        """Vérification URLVoid (gratuit)"""
        cache_key = f"urlvoid_{self.domain}"
        cached = cache.get(cache_key, 'reputation')
        if cached:
            return cached
        
        self.log_verbose("Vérification URLVoid...")
        
        urlvoid_info = {
            'url': f"https://www.urlvoid.com/scan/{self.domain}/",
            'reputation': 'unknown'
        }
        
        try:
            # URLVoid ne fournit pas d'API gratuite, mais on peut générer le lien
            # Pour une vérification automatique, il faudrait une clé API payante
            urlvoid_info['note'] = "Vérification manuelle requise via le lien fourni"
            
        except Exception as e:
            urlvoid_info['error'] = str(e)
        
        cache.set(cache_key, urlvoid_info, 'reputation')
        return urlvoid_info
    
    def check_phishtank(self) -> Dict:
        """Vérification PhishTank"""
        cache_key = f"phishtank_{self.domain}"
        cached = cache.get(cache_key, 'reputation')
        if cached:
            return cached
        
        self.log_verbose("Vérification PhishTank...")
        
        phishtank_info = {
            'is_phishing': False,
            'details': None
        }
        
        try:
            # PhishTank API (gratuite mais limitée)
            url = "https://checkurl.phishtank.com/checkurl/"
            data = {
                'url': f"http://{self.domain}",
                'format': 'json'
            }
            
            response = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                result = response.json()
                if 'results' in result:
                    phishtank_info['is_phishing'] = result['results'].get('in_database', False)
                    if phishtank_info['is_phishing']:
                        phishtank_info['details'] = result['results']
            
        except Exception as e:
            phishtank_info['error'] = str(e)
        
        cache.set(cache_key, phishtank_info, 'reputation')
        return phishtank_info
    
    def check_malware_domains(self) -> Dict:
        """Vérification contre les listes de domaines malveillants"""
        cache_key = f"malware_{self.domain}"
        cached = cache.get(cache_key, 'reputation')
        if cached:
            return cached
        
        self.log_verbose("Vérification listes de malware...")
        
        malware_info = {
            'blacklisted': False,
            'sources': [],
            'details': {}
        }
        
        # Listes publiques de domaines malveillants
        blacklists = {
            'malwaredomains': 'http://mirror1.malwaredomains.com/files/justdomains',
            'phishing_army': 'https://phishing.army/download/phishing_army_blocklist.txt'
        }
        
        for source, url in blacklists.items():
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    domains = response.text.lower().split('\n')
                    if self.domain.lower() in domains:
                        malware_info['blacklisted'] = True
                        malware_info['sources'].append(source)
                        malware_info['details'][source] = 'Domain found in blacklist'
                        
            except Exception as e:
                malware_info['details'][source] = f'Error checking: {str(e)}'
        
        cache.set(cache_key, malware_info, 'reputation')
        return malware_info
    
    def check_certificate_transparency(self) -> Dict:
        """Vérification des logs de transparence des certificats"""
        cache_key = f"ct_{self.domain}"
        cached = cache.get(cache_key, 'reputation')
        if cached:
            return cached
        
        self.log_verbose("Vérification Certificate Transparency...")
        
        ct_info = {
            'certificates_found': 0,
            'suspicious_patterns': [],
            'recent_certificates': []
        }
        
        try:
            # Utiliser crt.sh pour vérifier les certificats récents
            url = f"https://crt.sh/?q={self.domain}&output=json"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                certificates = response.json()
                ct_info['certificates_found'] = len(certificates)
                
                # Analyser les certificats récents (30 derniers jours)
                from datetime import datetime, timedelta
                recent_threshold = datetime.now() - timedelta(days=30)
                
                for cert in certificates[:10]:  # Limiter à 10 pour éviter trop de données
                    try:
                        not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                        if not_before > recent_threshold:
                            ct_info['recent_certificates'].append({
                                'id': cert['id'],
                                'not_before': cert['not_before'],
                                'not_after': cert['not_after'],
                                'name_value': cert['name_value']
                            })
                    except:
                        continue
                
                # Détecter des patterns suspects
                all_names = [cert.get('name_value', '') for cert in certificates]
                suspicious_keywords = ['phishing', 'secure', 'verify', 'update', 'login']
                
                for name in all_names:
                    for keyword in suspicious_keywords:
                        if keyword in name.lower() and keyword not in self.domain.lower():
                            ct_info['suspicious_patterns'].append(f"Suspicious subdomain: {name}")
                            break
        
        except Exception as e:
            ct_info['error'] = str(e)
        
        cache.set(cache_key, ct_info, 'reputation')
        return ct_info
    
    def calculate_reputation_score(self, vt_results: Dict, malware_results: Dict, 
                                 phishtank_results: Dict, ct_results: Dict) -> Dict:
        """Calcule un score de réputation global"""
        score = 100  # Score de base
        details = []
        
        # VirusTotal
        if vt_results.get('scan_results'):
            malicious = vt_results['scan_results'].get('malicious', 0)
            suspicious = vt_results['scan_results'].get('suspicious', 0)
            
            if malicious > 0:
                penalty = min(malicious * 10, 50)
                score -= penalty
                details.append(f"VirusTotal: {malicious} détections malveillantes (-{penalty} pts)")
            
            if suspicious > 0:
                penalty = min(suspicious * 5, 25)
                score -= penalty
                details.append(f"VirusTotal: {suspicious} détections suspectes (-{penalty} pts)")
        
        # Listes de malware
        if malware_results.get('blacklisted'):
            score -= 40
            sources = ', '.join(malware_results.get('sources', []))
            details.append(f"Blacklisté sur: {sources} (-40 pts)")
        
        # PhishTank
        if phishtank_results.get('is_phishing'):
            score -= 50
            details.append("Identifié comme phishing par PhishTank (-50 pts)")
        
        # Certificate Transparency (patterns suspects)
        suspicious_patterns = len(ct_results.get('suspicious_patterns', []))
        if suspicious_patterns > 0:
            penalty = min(suspicious_patterns * 5, 20)
            score -= penalty
            details.append(f"Patterns suspects dans les certificats (-{penalty} pts)")
        
        score = max(score, 0)  # Score minimum de 0
        
        if score >= 80:
            level = "EXCELLENT"
        elif score >= 60:
            level = "BON"
        elif score >= 40:
            level = "MOYEN"
        elif score >= 20:
            level = "FAIBLE"
        else:
            level = "CRITIQUE"
        
        return {
            'score': score,
            'level': level,
            'details': details
        }