#!/usr/bin/env python3
"""
Système de monitoring et d'alertes avancé pour NetTrace

Fonctionnalités:
- Surveillance continue des domaines
- Détection automatique des changements
- Alertes multi-canaux (email, webhook, Slack)
- Historique des modifications
- Scoring des changements par criticité
"""

import json
import time
import smtplib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Imports locaux
from config.settings import NOTIFICATION_SETTINGS, REPORTS_DIR
from core.cache import cache
from core.display import print_info, print_success, print_warning, print_error

class MonitoringSystem:
    """
    Système de monitoring avancé des domaines
    
    Surveille automatiquement les changements sur les domaines et envoie des alertes
    en temps réel via email, webhook ou Slack.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.monitoring_file = REPORTS_DIR / "monitoring.json"
        self.alerts_file = REPORTS_DIR / "alerts_history.json"
        self.load_monitoring_data()
        self.load_alerts_history()
    
    def log_verbose(self, message: str):
        """Log en mode verbeux"""
        if self.verbose:
            print_info(f"[MONITOR] {message}")
    
    def load_monitoring_data(self):
        """Charge les données de monitoring"""
        if self.monitoring_file.exists():
            try:
                with open(self.monitoring_file, 'r', encoding='utf-8') as f:
                    self.monitoring_data = json.load(f)
            except Exception:
                self.monitoring_data = {'domains': {}}
        else:
            self.monitoring_data = {'domains': {}}
    
    def load_alerts_history(self):
        """Charge l'historique des alertes"""
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r', encoding='utf-8') as f:
                    self.alerts_history = json.load(f)
            except Exception:
                self.alerts_history = {'alerts': []}
        else:
            self.alerts_history = {'alerts': []}
    
    def save_monitoring_data(self):
        """Sauvegarde les données de monitoring"""
        try:
            with open(self.monitoring_file, 'w', encoding='utf-8') as f:
                json.dump(self.monitoring_data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print_error(f"Erreur sauvegarde monitoring: {str(e)}")
    
    def save_alerts_history(self):
        """Sauvegarde l'historique des alertes"""
        try:
            with open(self.alerts_file, 'w', encoding='utf-8') as f:
                json.dump(self.alerts_history, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print_error(f"Erreur sauvegarde alertes: {str(e)}")
    
    def add_domain_monitoring(self, domain: str, check_interval: int = 3600):
        """
        Ajoute un domaine au monitoring
        
        Args:
            domain: Domaine à surveiller
            check_interval: Intervalle de vérification en secondes (défaut: 1h)
        """
        self.log_verbose(f"Ajout du domaine {domain} au monitoring")
        
        if domain not in self.monitoring_data['domains']:
            self.monitoring_data['domains'][domain] = {
                'added_date': datetime.now().isoformat(),
                'check_interval': check_interval,
                'last_check': None,
                'next_check': (datetime.now() + timedelta(seconds=check_interval)).isoformat(),
                'alerts': [],
                'history': [],
                'alert_settings': {
                    'dns_changes': True,
                    'whois_changes': True,
                    'ssl_changes': True,
                    'subdomain_changes': True,
                    'security_changes': True
                }
            }
            self.save_monitoring_data()
            print_success(f"✅ Domaine {domain} ajouté au monitoring")
            return True
        else:
            print_warning(f"⚠️  Domaine {domain} déjà en monitoring")
        return False
    
    def remove_domain_monitoring(self, domain: str):
        """Retire un domaine du monitoring"""
        if domain in self.monitoring_data['domains']:
            del self.monitoring_data['domains'][domain]
            self.save_monitoring_data()
            print_success(f"✅ Domaine {domain} retiré du monitoring")
            return True
        else:
            print_warning(f"⚠️  Domaine {domain} n'est pas en monitoring")
        return False
    
    def list_monitored_domains(self) -> List[Dict]:
        """Liste tous les domaines en monitoring"""
        domains_info = []
        for domain, data in self.monitoring_data['domains'].items():
            domains_info.append({
                'domain': domain,
                'added_date': data['added_date'],
                'last_check': data.get('last_check'),
                'next_check': data.get('next_check'),
                'alerts_count': len(data.get('alerts', [])),
                'check_interval': data['check_interval']
            })
        return domains_info
    
    def get_domain_alerts(self, domain: str, days: int = 7) -> List[Dict]:
        """Récupère les alertes récentes pour un domaine"""
        if domain not in self.monitoring_data['domains']:
            return []
        
        alerts = self.monitoring_data['domains'][domain].get('alerts', [])
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_alerts = []
        for alert in alerts:
            try:
                alert_date = datetime.fromisoformat(alert['timestamp'])
                if alert_date > cutoff_date:
                    recent_alerts.append(alert)
            except:
                continue
        
        return recent_alerts
    
    def check_domain_changes(self, domain: str, current_analysis: Dict) -> List[Dict]:
        """
        Vérifie les changements sur un domaine et génère des alertes
        
        Args:
            domain: Domaine à vérifier
            current_analysis: Résultats de l'analyse actuelle
            
        Returns:
            Liste des changements détectés
        """
        changes = []
        
        if domain not in self.monitoring_data['domains']:
            return changes
        
        domain_data = self.monitoring_data['domains'][domain]
        alert_settings = domain_data.get('alert_settings', {})
        history = domain_data.get('history', [])
        
        if not history:
            # Premier scan, pas de comparaison possible
            self._save_analysis_to_history(domain, current_analysis)
            self.log_verbose(f"Premier scan pour {domain}, aucune comparaison possible")
            return changes
        
        last_analysis = history[-1]['analysis']
        
        # Vérifier les changements DNS (si activé)
        if alert_settings.get('dns_changes', True):
            dns_changes = self._compare_dns_records(
                last_analysis.get('dns', {}),
                current_analysis.get('dns', {})
            )
            changes.extend(dns_changes)
        
        # Vérifier les changements WHOIS (si activé)
        if alert_settings.get('whois_changes', True):
            whois_changes = self._compare_whois_data(
                last_analysis.get('whois', {}),
                current_analysis.get('whois', {})
            )
            changes.extend(whois_changes)
        
        # Vérifier les changements SSL (si activé)
        if alert_settings.get('ssl_changes', True):
            ssl_changes = self._compare_ssl_certificates(
                last_analysis.get('ssl', {}),
                current_analysis.get('ssl', {})
            )
            changes.extend(ssl_changes)
        
        # Vérifier les changements de sous-domaines (si activé)
        if alert_settings.get('subdomain_changes', True):
            subdomain_changes = self._compare_subdomains(
                last_analysis.get('subdomains', []),
                current_analysis.get('subdomains', [])
            )
            changes.extend(subdomain_changes)
        
        # Vérifier les changements de sécurité (si activé)
        if alert_settings.get('security_changes', True):
            security_changes = self._compare_security_headers(
                last_analysis.get('security', {}),
                current_analysis.get('security', {})
            )
            changes.extend(security_changes)
        
        # Sauvegarder la nouvelle analyse
        self._save_analysis_to_history(domain, current_analysis)
        
        # Enregistrer les alertes
        if changes:
            self.log_verbose(f"{len(changes)} changements détectés pour {domain}")
            domain_data['alerts'].extend(changes)
            domain_data['last_check'] = datetime.now().isoformat()
            domain_data['next_check'] = (datetime.now() + timedelta(seconds=domain_data['check_interval'])).isoformat()
            self.save_monitoring_data()
            
            # Ajouter à l'historique global des alertes
            for change in changes:
                change['domain'] = domain
                self.alerts_history['alerts'].append(change)
            
            # Garder seulement les 1000 dernières alertes
            if len(self.alerts_history['alerts']) > 1000:
                self.alerts_history['alerts'] = self.alerts_history['alerts'][-1000:]
            
            self.save_alerts_history()
        else:
            domain_data['last_check'] = datetime.now().isoformat()
            domain_data['next_check'] = (datetime.now() + timedelta(seconds=domain_data['check_interval'])).isoformat()
            self.save_monitoring_data()
        
        return changes
    
    def _compare_subdomains(self, old_subdomains: List, new_subdomains: List) -> List[Dict]:
        """Compare les listes de sous-domaines"""
        changes = []
        
        old_set = set(old_subdomains)
        new_set = set(new_subdomains)
        
        added = new_set - old_set
        removed = old_set - new_set
        
        if added:
            changes.append({
                'type': 'subdomains_added',
                'count': len(added),
                'subdomains': list(added)[:10],  # Limiter à 10 pour l'affichage
                'timestamp': datetime.now().isoformat(),
                'severity': 'medium' if len(added) < 5 else 'high'
            })
        
        if removed:
            changes.append({
                'type': 'subdomains_removed',
                'count': len(removed),
                'subdomains': list(removed)[:10],
                'timestamp': datetime.now().isoformat(),
                'severity': 'high'  # Suppression toujours critique
            })
        
        return changes
    
    def _compare_security_headers(self, old_security: Dict, new_security: Dict) -> List[Dict]:
        """Compare les headers de sécurité"""
        changes = []
        
        old_headers = old_security.get('headers', {})
        new_headers = new_security.get('headers', {})
        
        # Vérifier les headers ajoutés/supprimés
        for header in set(list(old_headers.keys()) + list(new_headers.keys())):
            old_present = self._is_header_present(old_headers.get(header))
            new_present = self._is_header_present(new_headers.get(header))
            
            if old_present != new_present:
                if new_present and not old_present:
                    changes.append({
                        'type': 'security_header_added',
                        'header': header,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'low'
                    })
                elif old_present and not new_present:
                    changes.append({
                        'type': 'security_header_removed',
                        'header': header,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'high'
                    })
        
        # Vérifier les changements de score de sécurité
        old_score = old_security.get('score', 0)
        new_score = new_security.get('score', 0)
        
        if abs(old_score - new_score) >= 10:  # Changement significatif
            changes.append({
                'type': 'security_score_changed',
                'old_score': old_score,
                'new_score': new_score,
                'change': new_score - old_score,
                'timestamp': datetime.now().isoformat(),
                'severity': 'medium' if new_score > old_score else 'high'
            })
        
        return changes
    
    def _is_header_present(self, header_data) -> bool:
        """Détermine si un header de sécurité est présent"""
        if isinstance(header_data, dict):
            return header_data.get('present', False)
        elif isinstance(header_data, bool):
            return header_data
        elif isinstance(header_data, int):
            return header_data > 0
        return False
    
    def _compare_dns_records(self, old_dns: Dict, new_dns: Dict) -> List[Dict]:
        """Compare les enregistrements DNS"""
        changes = []
        
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            old_records = set(old_dns.get(record_type, []))
            new_records = set(new_dns.get(record_type, []))
            
            added = new_records - old_records
            removed = old_records - new_records
            
            if added:
                changes.append({
                    'type': 'dns_added',
                    'record_type': record_type,
                    'values': list(added),
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high' if record_type in ['A', 'AAAA', 'MX'] else 'medium'
                })
            
            if removed:
                changes.append({
                    'type': 'dns_removed',
                    'record_type': record_type,
                    'values': list(removed),
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high'
                })
        
        return changes
    
    def _compare_whois_data(self, old_whois: Dict, new_whois: Dict) -> List[Dict]:
        """Compare les données WHOIS"""
        changes = []
        
        important_fields = ['registrar', 'registrant', 'expiration_date']
        
        for field in important_fields:
            old_value = old_whois.get(field)
            new_value = new_whois.get(field)
            
            if old_value != new_value and old_value and new_value:
                changes.append({
                    'type': 'whois_changed',
                    'field': field,
                    'old_value': old_value,
                    'new_value': new_value,
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high' if field in ['registrar', 'registrant'] else 'medium'
                })
        
        return changes
    
    def _compare_ssl_certificates(self, old_ssl: Dict, new_ssl: Dict) -> List[Dict]:
        """Compare les certificats SSL"""
        changes = []
        
        old_expiry = old_ssl.get('expiry_date')
        new_expiry = new_ssl.get('expiry_date')
        
        if old_expiry != new_expiry and old_expiry and new_expiry:
            changes.append({
                'type': 'ssl_certificate_changed',
                'old_expiry': old_expiry,
                'new_expiry': new_expiry,
                'timestamp': datetime.now().isoformat(),
                'severity': 'medium'
            })
        
        old_issuer = old_ssl.get('issuer', {}).get('organizationName')
        new_issuer = new_ssl.get('issuer', {}).get('organizationName')
        
        if old_issuer != new_issuer and old_issuer and new_issuer:
            changes.append({
                'type': 'ssl_issuer_changed',
                'old_issuer': old_issuer,
                'new_issuer': new_issuer,
                'timestamp': datetime.now().isoformat(),
                'severity': 'high'
            })
        
        return changes
    
    def _save_analysis_to_history(self, domain: str, analysis: Dict):
        """Sauvegarde une analyse dans l'historique"""
        domain_data = self.monitoring_data['domains'][domain]
        
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis
        }
        
        domain_data['history'].append(history_entry)
        
        # Garder seulement les 20 dernières analyses
        if len(domain_data['history']) > 20:
            domain_data['history'] = domain_data['history'][-20:]
    
    def run_monitoring_check(self) -> Dict:
        """
        Lance une vérification de monitoring pour tous les domaines
        
        Returns:
            Statistiques de la vérification
        """
        from utils import DomainAnalyzer
        
        stats = {
            'domains_checked': 0,
            'domains_with_changes': 0,
            'total_changes': 0,
            'alerts_sent': 0,
            'errors': []
        }
        
        current_time = datetime.now()
        
        for domain, data in self.monitoring_data['domains'].items():
            try:
                # Vérifier si c'est le moment de checker
                next_check = datetime.fromisoformat(data.get('next_check', current_time.isoformat()))
                
                if current_time < next_check:
                    continue
                
                self.log_verbose(f"Vérification de {domain}...")
                
                # Lancer l'analyse
                analyzer = DomainAnalyzer(domain, verbose=self.verbose)
                results = analyzer.run_standard_analysis()
                
                if results and 'analysis' in results:
                    # Vérifier les changements
                    changes = self.check_domain_changes(domain, results['analysis'])
                    
                    stats['domains_checked'] += 1
                    
                    if changes:
                        stats['domains_with_changes'] += 1
                        stats['total_changes'] += len(changes)
                        
                        # Envoyer les alertes
                        if self.send_alert_email(domain, changes):
                            stats['alerts_sent'] += 1
                        
                        if self.send_webhook_alert(domain, changes):
                            stats['alerts_sent'] += 1
                        
                        if self.send_slack_alert(domain, changes):
                            stats['alerts_sent'] += 1
                        
                        print_warning(f"⚠️  {len(changes)} changements détectés sur {domain}")
                    else:
                        print_success(f"✅ Aucun changement sur {domain}")
                
            except Exception as e:
                error_msg = f"Erreur monitoring {domain}: {str(e)}"
                stats['errors'].append(error_msg)
                self.log_verbose(error_msg)
        
        return stats
    
    def send_alert_email(self, domain: str, changes: List[Dict]):
        """Envoie une alerte par email"""
        if not NOTIFICATION_SETTINGS['email']['enabled']:
            return False
        
        try:
            smtp_config = NOTIFICATION_SETTINGS['email']
            
            msg = MIMEMultipart()
            msg['From'] = smtp_config['username']
            msg['To'] = smtp_config['username']  # Envoyer à soi-même
            msg['Subject'] = f"NetTrace Alert - Changements détectés sur {domain}"
            
            body = self._format_alert_email(domain, changes)
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            
            text = msg.as_string()
            server.sendmail(smtp_config['username'], smtp_config['username'], text)
            server.quit()
            
            self.log_verbose(f"Email envoyé pour {domain}")
            return True
            
        except Exception as e:
            print_error(f"Erreur envoi email: {str(e)}")
            return False
    
    def send_webhook_alert(self, domain: str, changes: List[Dict]):
        """Envoie une alerte via webhook"""
        if not NOTIFICATION_SETTINGS['webhook']['enabled']:
            return False
        
        try:
            webhook_url = NOTIFICATION_SETTINGS['webhook']['url']
            
            payload = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'changes_count': len(changes),
                'changes': changes
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            self.log_verbose(f"Webhook envoyé pour {domain}: {response.status_code}")
            return response.status_code == 200
            
        except Exception as e:
            print_error(f"Erreur webhook: {str(e)}")
            return False
    
    def send_slack_alert(self, domain: str, changes: List[Dict]):
        """Envoie une alerte Slack"""
        if not NOTIFICATION_SETTINGS['slack']['enabled']:
            return False
        
        try:
            webhook_url = NOTIFICATION_SETTINGS['slack']['webhook_url']
            
            # Formater le message Slack
            severity_emoji = {
                'low': '🟢',
                'medium': '🟡',
                'high': '🔴'
            }
            
            max_severity = max([c.get('severity', 'low') for c in changes], key=lambda x: self._get_severity_level(x))
            emoji = severity_emoji.get(max_severity, '⚪')
            
            text = f"{emoji} *NetTrace Alert - {domain}*\n"
            text += f"📊 {len(changes)} changements détectés\n"
            text += f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            for change in changes[:5]:  # Limiter à 5 changements
                change_type = change.get('type', 'unknown').replace('_', ' ').title()
                text += f"• *{change_type}*"
                if change.get('record_type'):
                    text += f" ({change['record_type']})"
                text += f" - {change.get('severity', 'unknown').upper()}\n"
            
            if len(changes) > 5:
                text += f"... et {len(changes) - 5} autres changements\n"
            
            payload = {
                'text': text,
                'username': NOTIFICATION_SETTINGS['slack']['username'],
                'channel': NOTIFICATION_SETTINGS['slack']['channel']
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            self.log_verbose(f"Slack envoyé pour {domain}: {response.status_code}")
            return response.status_code == 200
            
        except Exception as e:
            print_error(f"Erreur Slack: {str(e)}")
            return False
    
    def _get_severity_level(self, severity: str) -> int:
        """Convertit la sévérité en niveau numérique"""
        levels = {'low': 1, 'medium': 2, 'high': 3}
        return levels.get(severity, 1)
    
    def _format_alert_email(self, domain: str, changes: List[Dict]) -> str:
        """Formate l'email d'alerte"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #f44336; color: white; padding: 15px; text-align: center; }}
                .change {{ margin: 10px 0; padding: 10px; border-left: 4px solid #2196F3; }}
                .severity-high {{ border-left-color: #f44336; }}
                .severity-medium {{ border-left-color: #ff9800; }}
                .severity-low {{ border-left-color: #4caf50; }}
                .stats {{ background-color: #f5f5f5; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 NetTrace Alert - {domain}</h2>
                <p>{len(changes)} changements détectés</p>
            </div>
            
            <div class="stats">
                <strong>Résumé:</strong><br>
                • Domaine: {domain}<br>
                • Changements: {len(changes)}<br>
                • Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            </div>
            
            <p>Des changements ont été détectés sur le domaine <strong>{domain}</strong>:</p>
            
        """
        
        for change in changes:
            severity_class = f"severity-{change.get('severity', 'low')}"
            change_type = change.get('type', 'unknown').replace('_', ' ').title()
            
            html += f"""
            <div class="change {severity_class}">
                <h3>{change_type}</h3>
                <p><strong>Timestamp:</strong> {change.get('timestamp')}</p>
                <p><strong>Sévérité:</strong> {change.get('severity', 'unknown').upper()}</p>
            """
            
            if change.get('record_type'):
                html += f"<p><strong>Type d'enregistrement:</strong> {change['record_type']}</p>"
            
            if change.get('values'):
                html += f"<p><strong>Valeurs:</strong> {', '.join(change['values'])}</p>"
            
            if change.get('old_value') and change.get('new_value'):
                html += f"""
                <p><strong>Ancienne valeur:</strong> {change['old_value']}</p>
                <p><strong>Nouvelle valeur:</strong> {change['new_value']}</p>
                """
            
            if change.get('count'):
                html += f"<p><strong>Nombre:</strong> {change['count']}</p>"
            
            html += "</div>"
        
        html += """
            <p>Vérifiez votre domaine avec NetTrace pour plus de détails.</p>
            <p><em>Cet email a été généré automatiquement par NetTrace.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def get_monitoring_status(self) -> Dict:
        """Retourne le statut détaillé du monitoring"""
        domains = self.monitoring_data.get('domains', {})
        
        status = {
            'total_domains': len(domains),
            'domains_due_check': 0,
            'total_alerts_7d': 0,
            'total_alerts_24h': 0,
            'domains_info': [],
            'system_status': 'active' if domains else 'inactive'
        }
        
        current_time = datetime.now()
        cutoff_7d = current_time - timedelta(days=7)
        cutoff_24h = current_time - timedelta(hours=24)
        
        for domain, data in domains.items():
            # Vérifier si le domaine doit être vérifié
            next_check = datetime.fromisoformat(data.get('next_check', current_time.isoformat()))
            if current_time >= next_check:
                status['domains_due_check'] += 1
            
            # Compter les alertes récentes
            alerts = data.get('alerts', [])
            alerts_7d = 0
            alerts_24h = 0
            
            for alert in alerts:
                try:
                    alert_time = datetime.fromisoformat(alert['timestamp'])
                    if alert_time > cutoff_7d:
                        alerts_7d += 1
                    if alert_time > cutoff_24h:
                        alerts_24h += 1
                except:
                    continue
            
            status['total_alerts_7d'] += alerts_7d
            status['total_alerts_24h'] += alerts_24h
            
            # Informations détaillées du domaine
            status['domains_info'].append({
                'domain': domain,
                'last_check': data.get('last_check'),
                'next_check': data.get('next_check'),
                'alerts_7d': alerts_7d,
                'alerts_24h': alerts_24h,
                'check_interval': data.get('check_interval', 3600),
                'due_check': current_time >= next_check
            })
        
        return status