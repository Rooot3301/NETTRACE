#!/usr/bin/env python3
"""
Système de monitoring et d'alertes
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

from config.settings import NOTIFICATION_SETTINGS, REPORTS_DIR
from core.cache import cache
from core.display import print_info, print_success, print_warning, print_error

class MonitoringSystem:
    """Système de monitoring des domaines"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.monitoring_file = REPORTS_DIR / "monitoring.json"
        self.load_monitoring_data()
    
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
    
    def save_monitoring_data(self):
        """Sauvegarde les données de monitoring"""
        try:
            with open(self.monitoring_file, 'w', encoding='utf-8') as f:
                json.dump(self.monitoring_data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print_error(f"Erreur sauvegarde monitoring: {str(e)}")
    
    def add_domain_monitoring(self, domain: str, check_interval: int = 3600):
        """Ajoute un domaine au monitoring"""
        self.log_verbose(f"Ajout du domaine {domain} au monitoring")
        
        if domain not in self.monitoring_data['domains']:
            self.monitoring_data['domains'][domain] = {
                'added_date': datetime.now().isoformat(),
                'check_interval': check_interval,
                'last_check': None,
                'alerts': [],
                'history': []
            }
            self.save_monitoring_data()
            return True
        return False
    
    def remove_domain_monitoring(self, domain: str):
        """Retire un domaine du monitoring"""
        if domain in self.monitoring_data['domains']:
            del self.monitoring_data['domains'][domain]
            self.save_monitoring_data()
            return True
        return False
    
    def check_domain_changes(self, domain: str, current_analysis: Dict) -> List[Dict]:
        """Vérifie les changements sur un domaine"""
        changes = []
        
        if domain not in self.monitoring_data['domains']:
            return changes
        
        domain_data = self.monitoring_data['domains'][domain]
        history = domain_data.get('history', [])
        
        if not history:
            # Premier scan, pas de comparaison possible
            self._save_analysis_to_history(domain, current_analysis)
            return changes
        
        last_analysis = history[-1]['analysis']
        
        # Vérifier les changements DNS
        dns_changes = self._compare_dns_records(
            last_analysis.get('dns', {}),
            current_analysis.get('dns', {})
        )
        changes.extend(dns_changes)
        
        # Vérifier les changements WHOIS
        whois_changes = self._compare_whois_data(
            last_analysis.get('whois', {}),
            current_analysis.get('whois', {})
        )
        changes.extend(whois_changes)
        
        # Vérifier les changements SSL
        ssl_changes = self._compare_ssl_certificates(
            last_analysis.get('ssl', {}),
            current_analysis.get('ssl', {})
        )
        changes.extend(ssl_changes)
        
        # Sauvegarder la nouvelle analyse
        self._save_analysis_to_history(domain, current_analysis)
        
        # Enregistrer les alertes
        if changes:
            domain_data['alerts'].extend(changes)
            domain_data['last_check'] = datetime.now().isoformat()
            self.save_monitoring_data()
        
        return changes
    
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
                    'severity': 'medium'
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
        
        # Garder seulement les 10 dernières analyses
        if len(domain_data['history']) > 10:
            domain_data['history'] = domain_data['history'][-10:]
    
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
            return response.status_code == 200
            
        except Exception as e:
            print_error(f"Erreur webhook: {str(e)}")
            return False
    
    def _format_alert_email(self, domain: str, changes: List[Dict]) -> str:
        """Formate l'email d'alerte"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #f44336; color: white; padding: 10px; }}
                .change {{ margin: 10px 0; padding: 10px; border-left: 4px solid #2196F3; }}
                .severity-high {{ border-left-color: #f44336; }}
                .severity-medium {{ border-left-color: #ff9800; }}
                .severity-low {{ border-left-color: #4caf50; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 NetTrace Alert - {domain}</h2>
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
            
            html += "</div>"
        
        html += """
            <p>Vérifiez votre domaine avec NetTrace pour plus de détails.</p>
        </body>
        </html>
        """
        
        return html
    
    def get_monitoring_status(self) -> Dict:
        """Retourne le statut du monitoring"""
        domains = self.monitoring_data.get('domains', {})
        
        status = {
            'total_domains': len(domains),
            'active_alerts': 0,
            'last_checks': {}
        }
        
        for domain, data in domains.items():
            alerts = data.get('alerts', [])
            recent_alerts = [
                alert for alert in alerts 
                if datetime.fromisoformat(alert['timestamp']) > datetime.now() - timedelta(days=7)
            ]
            status['active_alerts'] += len(recent_alerts)
            status['last_checks'][domain] = data.get('last_check')
        
        return status