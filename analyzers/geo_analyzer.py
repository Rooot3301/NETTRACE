#!/usr/bin/env python3
"""
Analyseur géographique et de géolocalisation
"""

import socket
import time
import requests
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import REQUEST_TIMEOUT
from core.cache import cache
from utils import print_info, print_success, print_warning

class GeoAnalyzer:
    """Analyseur géographique"""
    
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
    
    def log_verbose(self, message: str):
        """Log en mode verbeux"""
        if self.verbose:
            print_info(f"[GEO] {message}")
    
    def get_ip_addresses(self) -> List[str]:
        """Récupère les adresses IP du domaine"""
        ips = []
        try:
            # IPv4
            ipv4_list = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            ips.extend([ip[4][0] for ip in ipv4_list])
            
            # IPv6
            try:
                ipv6_list = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
                ips.extend([ip[4][0] for ip in ipv6_list])
            except socket.gaierror:
                pass  # IPv6 non disponible
                
        except socket.gaierror as e:
            self.log_verbose(f"Erreur résolution IP: {str(e)}")
        
        return list(set(ips))  # Supprimer les doublons
    
    def geolocate_ip(self, ip: str) -> Dict:
        """Géolocalise une adresse IP"""
        cache_key = f"geo_{ip}"
        cached = cache.get(cache_key, 'geolocation')
        if cached:
            return cached
        
        self.log_verbose(f"Géolocalisation de {ip}...")
        
        geo_info = {
            'ip': ip,
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'organization': None,
            'asn': None
        }
        
        # Utiliser plusieurs services de géolocalisation
        services = [
            self._geolocate_ipapi,
            self._geolocate_ipinfo,
            self._geolocate_freegeoip
        ]
        
        for service in services:
            try:
                result = service(ip)
                if result and result.get('country'):
                    geo_info.update(result)
                    break
            except Exception as e:
                self.log_verbose(f"Erreur service géolocalisation: {str(e)}")
                continue
        
        cache.set(cache_key, geo_info, 'geolocation')
        return geo_info
    
    def _geolocate_ipapi(self, ip: str) -> Optional[Dict]:
        """Géolocalisation via ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'asn': data.get('as')
                    }
        except Exception:
            pass
        return None
    
    def _geolocate_ipinfo(self, ip: str) -> Optional[Dict]:
        """Géolocalisation via ipinfo.io"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                loc = data.get('loc', '').split(',')
                
                return {
                    'country': data.get('country'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': float(loc[0]) if len(loc) > 0 and loc[0] else None,
                    'longitude': float(loc[1]) if len(loc) > 1 and loc[1] else None,
                    'timezone': data.get('timezone'),
                    'organization': data.get('org')
                }
        except Exception:
            pass
        return None
    
    def _geolocate_freegeoip(self, ip: str) -> Optional[Dict]:
        """Géolocalisation via freegeoip.app"""
        try:
            url = f"https://freegeoip.app/json/{ip}"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'region': data.get('region_name'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('time_zone')
                }
        except Exception:
            pass
        return None
    
    def analyze_latency(self, target_servers: List[str] = None) -> Dict:
        """Analyse la latence depuis différents points"""
        if target_servers is None:
            target_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']  # Google, Cloudflare, OpenDNS
        
        self.log_verbose("Analyse de latence...")
        
        latency_info = {
            'domain_latency': self._measure_latency(self.domain),
            'reference_latencies': {}
        }
        
        # Mesurer la latence vers des serveurs de référence
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_server = {
                executor.submit(self._measure_latency, server): server 
                for server in target_servers
            }
            
            for future in as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    latency = future.result()
                    latency_info['reference_latencies'][server] = latency
                except Exception as e:
                    latency_info['reference_latencies'][server] = {'error': str(e)}
        
        return latency_info
    
    def _measure_latency(self, host: str, port: int = 80, timeout: int = 5) -> Dict:
        """Mesure la latence vers un hôte"""
        latencies = []
        
        for i in range(3):  # 3 mesures
            try:
                start_time = time.time()
                sock = socket.create_connection((host, port), timeout=timeout)
                sock.close()
                latency = (time.time() - start_time) * 1000  # en ms
                latencies.append(latency)
            except Exception:
                continue
        
        if latencies:
            return {
                'min': min(latencies),
                'max': max(latencies),
                'avg': sum(latencies) / len(latencies),
                'measurements': len(latencies)
            }
        else:
            return {'error': 'Unable to measure latency'}
    
    def analyze_hosting_infrastructure(self) -> Dict:
        """Analyse l'infrastructure d'hébergement"""
        self.log_verbose("Analyse de l'infrastructure d'hébergement...")
        
        ips = self.get_ip_addresses()
        infrastructure = {
            'ip_addresses': ips,
            'geolocation': [],
            'hosting_providers': [],
            'countries': set(),
            'regions': set()
        }
        
        # Géolocaliser chaque IP
        for ip in ips:
            geo_info = self.geolocate_ip(ip)
            infrastructure['geolocation'].append(geo_info)
            
            if geo_info.get('country'):
                infrastructure['countries'].add(geo_info['country'])
            if geo_info.get('region'):
                infrastructure['regions'].add(geo_info['region'])
            if geo_info.get('organization'):
                infrastructure['hosting_providers'].append(geo_info['organization'])
        
        # Convertir les sets en listes pour la sérialisation JSON
        infrastructure['countries'] = list(infrastructure['countries'])
        infrastructure['regions'] = list(infrastructure['regions'])
        
        return infrastructure