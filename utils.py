#!/usr/bin/env python3
"""
Utilitaires pour NetTrace
"""

import re
import json
import subprocess
import time
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests
from colorama import init, Fore, Back, Style

# Initialisation de colorama
init(autoreset=True)

def print_banner():
    """Affiche la bannière de l'outil"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
███╗   ██╗███████╗████████╗████████╗██████╗  █████╗  ██████╗███████╗
████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██╔██╗ ██║█████╗     ██║      ██║   ██████╔╝███████║██║     █████╗  
██║╚██╗██║██╔══╝     ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
{Style.RESET_ALL}
{Fore.GREEN}🔍 Outil OSINT d'analyse de domaines - Sans APIs payantes{Style.RESET_ALL}
{Fore.BLUE}By: Assistant IA | Version: 1.0{Style.RESET_ALL}
    """
    print(banner)

def print_section(title):
    """Affiche une section avec style"""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}📋 {title.upper()}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'─' * (len(title) + 4)}{Style.RESET_ALL}")

def print_success(text):
    """Affiche un message de succès"""
    print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")

def print_error(text):
    """Affiche un message d'erreur"""
    print(f"{Fore.RED}{text}{Style.RESET_ALL}")

def print_warning(text):
    """Affiche un message d'avertissement"""
    print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")

def print_info(text):
    """Affiche un message d'information"""
    print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")

class DomainAnalyzer:
    """Classe principale pour l'analyse OSINT de domaines"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {}
        
    def log_verbose(self, message):
        """Log en mode verbeux"""
        if self.verbose:
            print(f"{Fore.MAGENTA}[DEBUG] {message}{Style.RESET_ALL}")
    
    def whois_lookup(self):
        """Effectue une recherche WHOIS"""
        print_section("WHOIS Lookup")
        whois_info = {}
        
        try:
            import whois
            self.log_verbose(f"Recherche WHOIS pour {self.domain}")
            
            w = whois.whois(self.domain)
            
            whois_info = {
                'registrar': str(w.registrar) if w.registrar else 'Non disponible',
                'creation_date': str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else 'Non disponible',
                'expiration_date': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else 'Non disponible',
                'registrant': str(w.registrant) if w.registrant else 'Non disponible',
                'status': str(w.status) if w.status else 'Non disponible',
                'name_servers': w.name_servers if w.name_servers else []
            }
            
            # Affichage
            print_info(f"🏢 Registrar: {whois_info['registrar']}")
            print_info(f"📅 Date de création: {whois_info['creation_date']}")
            print_info(f"⏰ Date d'expiration: {whois_info['expiration_date']}")
            print_info(f"👤 Propriétaire: {whois_info['registrant']}")
            print_info(f"📊 Statut: {whois_info['status']}")
            
            if whois_info['name_servers']:
                print_info(f"🌐 Serveurs DNS: {', '.join(whois_info['name_servers'][:3])}")
            
        except ImportError:
            print_error("❌ Module 'python-whois' non installé. Installation: pip install python-whois")
            whois_info['error'] = 'Module python-whois manquant'
        except Exception as e:
            print_error(f"❌ Erreur WHOIS: {str(e)}")
            whois_info['error'] = str(e)
        
        return whois_info
    
    def dns_resolution(self):
        """Effectue la résolution DNS"""
        print_section("Résolution DNS")
        dns_info = {}
        
        try:
            import dns.resolver
            
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
            
            for record_type in record_types:
                try:
                    self.log_verbose(f"Recherche enregistrement {record_type}")
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                    
                    print_info(f"🔍 {record_type}: {', '.join(dns_info[record_type][:3])}")
                    if len(dns_info[record_type]) > 3:
                        print_info(f"   ... et {len(dns_info[record_type])-3} autres")
                        
                except dns.resolver.NXDOMAIN:
                    dns_info[record_type] = []
                except dns.resolver.NoAnswer:
                    dns_info[record_type] = []
                except Exception as e:
                    self.log_verbose(f"Erreur {record_type}: {str(e)}")
                    dns_info[record_type] = []
                    
        except ImportError:
            print_error("❌ Module 'dnspython' non installé. Installation: pip install dnspython")
            dns_info['error'] = 'Module dnspython manquant'
        except Exception as e:
            print_error(f"❌ Erreur DNS: {str(e)}")
            dns_info['error'] = str(e)
        
        return dns_info
    
    def find_subdomains(self):
        """Recherche de sous-domaines"""
        print_section("Extraction de sous-domaines")
        subdomains = set()
        
        # 1. Recherche via crt.sh
        try:
            self.log_verbose("Recherche via crt.sh")
            url = f"https://crt.sh/?q={self.domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value']
                    # Nettoyer et extraire les sous-domaines
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            subdomains.add(subdomain)
                
                print_success(f"✅ crt.sh: {len(subdomains)} sous-domaines trouvés")
            else:
                print_warning("⚠️  crt.sh: Aucune réponse")
                
        except Exception as e:
            print_error(f"❌ Erreur crt.sh: {str(e)}")
        
        # 2. Recherche via subfinder (si installé)
        try:
            self.log_verbose("Vérification de subfinder")
            result = subprocess.run(['subfinder', '-d', self.domain, '-silent'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                subfinder_subs = set(result.stdout.strip().split('\n'))
                subfinder_subs = {s.strip().lower() for s in subfinder_subs if s.strip()}
                subdomains.update(subfinder_subs)
                print_success(f"✅ subfinder: +{len(subfinder_subs)} sous-domaines")
            else:
                print_warning("⚠️  subfinder: Erreur d'exécution")
        except FileNotFoundError:
            print_warning("⚠️  subfinder: Non installé")
        except subprocess.TimeoutExpired:
            print_warning("⚠️  subfinder: Timeout")
        except Exception as e:
            self.log_verbose(f"Erreur subfinder: {str(e)}")
        
        # 3. Recherche via amass (si installé)
        try:
            self.log_verbose("Vérification d'amass")
            result = subprocess.run(['amass', 'enum', '-d', self.domain, '-passive'], 
                                  capture_output=True, text=True, timeout=45)
            if result.returncode == 0:
                amass_subs = set(result.stdout.strip().split('\n'))
                amass_subs = {s.strip().lower() for s in amass_subs if s.strip()}
                subdomains.update(amass_subs)
                print_success(f"✅ amass: +{len(amass_subs)} sous-domaines")
            else:
                print_warning("⚠️  amass: Erreur d'exécution")
        except FileNotFoundError:
            print_warning("⚠️  amass: Non installé")
        except subprocess.TimeoutExpired:
            print_warning("⚠️  amass: Timeout")
        except Exception as e:
            self.log_verbose(f"Erreur amass: {str(e)}")
        
        # Nettoyage final
        clean_subdomains = []
        for sub in sorted(subdomains):
            if sub and '.' in sub and not sub.startswith('*'):
                clean_subdomains.append(sub)
        
        # Affichage des résultats
        print_info(f"🎯 Total: {len(clean_subdomains)} sous-domaines uniques")
        if clean_subdomains:
            print_info("📋 Quelques exemples:")
            for sub in clean_subdomains[:10]:
                print_info(f"   • {sub}")
            if len(clean_subdomains) > 10:
                print_info(f"   ... et {len(clean_subdomains)-10} autres")
        
        return clean_subdomains
    
    def virustotal_link(self):
        """Génère le lien VirusTotal"""
        print_section("VirusTotal")
        vt_link = f"https://www.virustotal.com/gui/domain/{self.domain}"
        print_info(f"🔗 Lien VirusTotal: {vt_link}")
        return vt_link
    
    def calculate_trust_score(self, whois_info, dns_info, subdomains):
        """Calcule un score de confiance sur 100"""
        print_section("Score de confiance")
        score = 0
        details = []
        
        # Critère 1: Ancienneté du domaine (30 points max)
        try:
            if 'creation_date' in whois_info and whois_info['creation_date'] != 'Non disponible':
                creation_str = whois_info['creation_date']
                # Extraction de la date
                if isinstance(creation_str, str):
                    # Essayer plusieurs formats de date
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%m-%Y', '%m/%d/%Y']:
                        try:
                            creation_date = datetime.strptime(creation_str.split(' ')[0], fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        # Si aucun format ne marche, essayer une extraction basique
                        import dateutil.parser
                        creation_date = dateutil.parser.parse(creation_str)
                    
                    age_days = (datetime.now() - creation_date).days
                    age_years = age_days / 365.25
                    
                    if age_years >= 10:
                        score += 30
                        details.append(f"✅ Domaine très ancien ({age_years:.1f} ans): +30 pts")
                    elif age_years >= 3:
                        score += 20
                        details.append(f"✅ Domaine mature ({age_years:.1f} ans): +20 pts")
                    elif age_years >= 1:
                        score += 10
                        details.append(f"⚠️  Domaine récent ({age_years:.1f} ans): +10 pts")
                    else:
                        details.append(f"❌ Domaine très récent ({age_years:.1f} ans): +0 pts")
        except Exception as e:
            details.append("❓ Âge du domaine indéterminable: +0 pts")
        
        # Critère 2: Complétude des enregistrements DNS (25 points max)
        dns_score = 0
        required_records = ['A', 'MX', 'NS']
        optional_records = ['AAAA', 'TXT']
        
        for record in required_records:
            if record in dns_info and dns_info[record]:
                dns_score += 8
        
        for record in optional_records:
            if record in dns_info and dns_info[record]:
                dns_score += 4
        
        dns_score = min(dns_score, 25)
        score += dns_score
        details.append(f"🌐 Enregistrements DNS: +{dns_score} pts")
        
        # Critère 3: Nombre de sous-domaines (20 points max)
        subdomain_count = len(subdomains)
        if subdomain_count >= 50:
            subdomain_score = 20
            details.append(f"🔍 Nombreux sous-domaines ({subdomain_count}): +20 pts")
        elif subdomain_count >= 20:
            subdomain_score = 15
            details.append(f"🔍 Sous-domaines multiples ({subdomain_count}): +15 pts")
        elif subdomain_count >= 5:
            subdomain_score = 10
            details.append(f"🔍 Quelques sous-domaines ({subdomain_count}): +10 pts")
        elif subdomain_count >= 1:
            subdomain_score = 5
            details.append(f"🔍 Peu de sous-domaines ({subdomain_count}): +5 pts")
        else:
            subdomain_score = 0
            details.append("🔍 Aucun sous-domaine trouvé: +0 pts")
        
        score += subdomain_score
        
        # Critère 4: Informations WHOIS (15 points max)
        whois_score = 0
        if 'registrar' in whois_info and whois_info['registrar'] != 'Non disponible':
            whois_score += 5
        if 'registrant' in whois_info and whois_info['registrant'] != 'Non disponible':
            whois_score += 5
        if 'status' in whois_info and whois_info['status'] != 'Non disponible':
            whois_score += 5
        
        score += whois_score
        details.append(f"📋 Informations WHOIS: +{whois_score} pts")
        
        # Critère 5: Stabilité (10 points max)
        stability_score = 10  # Score par défaut
        score += stability_score
        details.append(f"⚖️  Stabilité estimée: +{stability_score} pts")
        
        # Affichage du score
        if score >= 80:
            color = Fore.GREEN
            level = "ÉLEVÉ"
        elif score >= 60:
            color = Fore.YELLOW
            level = "MOYEN"
        else:
            color = Fore.RED
            level = "FAIBLE"
        
        print(f"{color}{Style.BRIGHT}🎯 Score de confiance: {score}/100 ({level}){Style.RESET_ALL}")
        print_info("\n📊 Détails du scoring:")
        for detail in details:
            print_info(f"   {detail}")
        
        return {
            'score': score,
            'level': level,
            'details': details
        }
    
    def run_full_analysis(self):
        """Lance l'analyse complète"""
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        # 1. WHOIS
        print_info("🔄 Étape 1/5: Recherche WHOIS...")
        results['analysis']['whois'] = self.whois_lookup()
        time.sleep(1)
        
        # 2. DNS
        print_info("\n🔄 Étape 2/5: Résolution DNS...")
        results['analysis']['dns'] = self.dns_resolution()
        time.sleep(1)
        
        # 3. Sous-domaines
        print_info("\n🔄 Étape 3/5: Recherche de sous-domaines...")
        results['analysis']['subdomains'] = self.find_subdomains()
        time.sleep(1)
        
        # 4. VirusTotal
        print_info("\n🔄 Étape 4/5: Lien VirusTotal...")
        results['analysis']['virustotal_link'] = self.virustotal_link()
        time.sleep(1)
        
        # 5. Score de confiance
        print_info("\n🔄 Étape 5/5: Calcul du score de confiance...")
        results['analysis']['trust_score'] = self.calculate_trust_score(
            results['analysis']['whois'],
            results['analysis']['dns'],
            results['analysis']['subdomains']
        )
        
        return results
    
    def display_results(self, results):
        """Affiche un résumé des résultats"""
        print_section("RÉSUMÉ DE L'ANALYSE")
        
        domain = results['domain']
        analysis = results['analysis']
        
        print_info(f"🎯 Domaine analysé: {domain}")
        print_info(f"📅 Date d'analyse: {results['timestamp']}")
        
        # Statistiques rapides
        stats = []
        
        if 'whois' in analysis and 'registrar' in analysis['whois']:
            stats.append(f"Registrar: {analysis['whois']['registrar']}")
        
        if 'dns' in analysis:
            dns_records = sum(1 for records in analysis['dns'].values() if isinstance(records, list) and records)
            stats.append(f"Enregistrements DNS: {dns_records}")
        
        if 'subdomains' in analysis:
            stats.append(f"Sous-domaines: {len(analysis['subdomains'])}")
        
        if 'trust_score' in analysis:
            score = analysis['trust_score']['score']
            level = analysis['trust_score']['level']
            stats.append(f"Score de confiance: {score}/100 ({level})")
        
        for stat in stats:
            print_info(f"📊 {stat}")
    
    def export_results(self, results, filename, format_type='json'):
        """Exporte les résultats"""
        try:
            if format_type == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            
            elif format_type == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=" * 60 + "\n")
                    f.write("NETTRACE - RAPPORT D'ANALYSE OSINT\n")
                    f.write("=" * 60 + "\n\n")
                    
                    f.write(f"Domaine: {results['domain']}\n")
                    f.write(f"Date: {results['timestamp']}\n\n")
                    
                    analysis = results['analysis']
                    
                    # WHOIS
                    if 'whois' in analysis:
                        f.write("WHOIS INFORMATION\n")
                        f.write("-" * 20 + "\n")
                        whois = analysis['whois']
                        for key, value in whois.items():
                            if key != 'error':
                                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                        f.write("\n")
                    
                    # DNS
                    if 'dns' in analysis:
                        f.write("ENREGISTREMENTS DNS\n")
                        f.write("-" * 20 + "\n")
                        for record_type, records in analysis['dns'].items():
                            if isinstance(records, list) and records:
                                f.write(f"{record_type}: {', '.join(records)}\n")
                        f.write("\n")
                    
                    # Sous-domaines
                    if 'subdomains' in analysis:
                        f.write("SOUS-DOMAINES\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"Total: {len(analysis['subdomains'])}\n")
                        for subdomain in analysis['subdomains'][:20]:
                            f.write(f"• {subdomain}\n")
                        if len(analysis['subdomains']) > 20:
                            f.write(f"... et {len(analysis['subdomains'])-20} autres\n")
                        f.write("\n")
                    
                    # Score de confiance
                    if 'trust_score' in analysis:
                        f.write("SCORE DE CONFIANCE\n")
                        f.write("-" * 20 + "\n")
                        trust = analysis['trust_score']
                        f.write(f"Score: {trust['score']}/100 ({trust['level']})\n")
                        f.write("Détails:\n")
                        for detail in trust['details']:
                            f.write(f"  {detail}\n")
                        f.write("\n")
                    
                    # VirusTotal
                    if 'virustotal_link' in analysis:
                        f.write("VIRUSTOTAL\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"Lien: {analysis['virustotal_link']}\n")
            
            return True
        except Exception as e:
            print_error(f"❌ Erreur lors de l'export: {str(e)}")
            return False