#!/usr/bin/env python3
"""
Générateur de rapports avancés
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from io import StringIO

from config.settings import REPORTS_DIR
from core.display import print_success, print_error

class ReportGenerator:
    """Générateur de rapports multi-formats"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def generate_json_report(self, results: Dict, filename: str) -> bool:
        """Génère un rapport JSON"""
        try:
            filepath = REPORTS_DIR / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception as e:
            print_error(f"Erreur génération JSON: {str(e)}")
            return False
    
    def generate_csv_report(self, results: Dict, filename: str) -> bool:
        """Génère un rapport CSV"""
        try:
            filepath = REPORTS_DIR / filename
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # En-têtes
                writer.writerow(['Domain', 'Timestamp', 'Category', 'Key', 'Value'])
                
                domain = results.get('domain', 'Unknown')
                timestamp = results.get('timestamp', datetime.now().isoformat())
                
                # Parcourir récursivement les résultats
                self._write_dict_to_csv(writer, results.get('analysis', {}), domain, timestamp)
            
            return True
        except Exception as e:
            print_error(f"Erreur génération CSV: {str(e)}")
            return False
    
    def _write_dict_to_csv(self, writer, data: Dict, domain: str, timestamp: str, category: str = ''):
        """Écrit récursivement un dictionnaire en CSV"""
        for key, value in data.items():
            current_category = f"{category}.{key}" if category else key
            
            if isinstance(value, dict):
                self._write_dict_to_csv(writer, value, domain, timestamp, current_category)
            elif isinstance(value, list):
                if value:  # Si la liste n'est pas vide
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            self._write_dict_to_csv(writer, item, domain, timestamp, f"{current_category}[{i}]")
                        else:
                            writer.writerow([domain, timestamp, current_category, f"item_{i}", str(item)])
                else:
                    writer.writerow([domain, timestamp, current_category, 'empty_list', ''])
            else:
                writer.writerow([domain, timestamp, current_category, key, str(value)])
    
    def generate_xml_report(self, results: Dict, filename: str) -> bool:
        """Génère un rapport XML"""
        try:
            filepath = REPORTS_DIR / filename
            
            root = ET.Element('nettrace_report')
            root.set('domain', results.get('domain', 'Unknown'))
            root.set('timestamp', results.get('timestamp', datetime.now().isoformat()))
            
            # Convertir le dictionnaire en XML
            analysis_elem = ET.SubElement(root, 'analysis')
            self._dict_to_xml(analysis_elem, results.get('analysis', {}))
            
            # Écrire le fichier
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            return True
        except Exception as e:
            print_error(f"Erreur génération XML: {str(e)}")
            return False
    
    def _dict_to_xml(self, parent: ET.Element, data: Dict):
        """Convertit récursivement un dictionnaire en XML"""
        for key, value in data.items():
            # Nettoyer le nom de l'élément
            clean_key = key.replace(' ', '_').replace('-', '_')
            elem = ET.SubElement(parent, clean_key)
            
            if isinstance(value, dict):
                self._dict_to_xml(elem, value)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_elem = ET.SubElement(elem, 'item')
                    item_elem.set('index', str(i))
                    if isinstance(item, dict):
                        self._dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                elem.text = str(value)
    
    def generate_html_report(self, results: Dict, filename: str) -> bool:
        """Génère un rapport HTML"""
        try:
            filepath = REPORTS_DIR / filename
            
            html_content = self._generate_html_content(results)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True
        except Exception as e:
            print_error(f"Erreur génération HTML: {str(e)}")
            return False
    
    def _generate_html_content(self, results: Dict) -> str:
        """Génère le contenu HTML du rapport"""
        domain = results.get('domain', 'Unknown')
        timestamp = results.get('timestamp', datetime.now().isoformat())
        analysis = results.get('analysis', {})
        
        html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NetTrace Report - {domain}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #007acc;
                }}
                .section {{
                    margin: 30px 0;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .section h2 {{
                    color: #007acc;
                    margin-top: 0;
                }}
                .score {{
                    display: inline-block;
                    padding: 10px 20px;
                    border-radius: 25px;
                    color: white;
                    font-weight: bold;
                }}
                .score.high {{ background-color: #4caf50; }}
                .score.medium {{ background-color: #ff9800; }}
                .score.low {{ background-color: #f44336; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 15px 0;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #f8f9fa;
                    font-weight: bold;
                }}
                .list-item {{
                    background-color: #f8f9fa;
                    padding: 5px 10px;
                    margin: 2px 0;
                    border-radius: 3px;
                    display: inline-block;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 NetTrace Report</h1>
                    <h2>{domain}</h2>
                    <p>Généré le: {timestamp}</p>
                </div>
        """
        
        # Section WHOIS
        if 'whois' in analysis:
            html += self._generate_whois_section(analysis['whois'])
        
        # Section DNS
        if 'dns' in analysis:
            html += self._generate_dns_section(analysis['dns'])
        
        # Section Technologies Web
        if 'web_technologies' in analysis:
            html += self._generate_web_tech_section(analysis['web_technologies'])
        
        # Section Sécurité
        if 'security' in analysis:
            html += self._generate_security_section(analysis['security'])
        
        # Section Géolocalisation
        if 'geolocation' in analysis:
            html += self._generate_geo_section(analysis['geolocation'])
        
        # Section Réputation
        if 'reputation' in analysis:
            html += self._generate_reputation_section(analysis['reputation'])
        
        # Section Scores
        if 'trust_score' in analysis or 'security_score' in analysis:
            html += self._generate_scores_section(analysis)
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_whois_section(self, whois_data: Dict) -> str:
        """Génère la section WHOIS"""
        html = """
        <div class="section">
            <h2>📋 Informations WHOIS</h2>
            <table>
        """
        
        fields = {
            'registrar': 'Registrar',
            'creation_date': 'Date de création',
            'expiration_date': 'Date d\'expiration',
            'registrant': 'Propriétaire',
            'status': 'Statut'
        }
        
        for key, label in fields.items():
            value = whois_data.get(key, 'Non disponible')
            html += f"<tr><th>{label}</th><td>{value}</td></tr>"
        
        html += "</table></div>"
        return html
    
    def _generate_dns_section(self, dns_data: Dict) -> str:
        """Génère la section DNS"""
        html = """
        <div class="section">
            <h2>🌐 Enregistrements DNS</h2>
        """
        
        for record_type, records in dns_data.items():
            if isinstance(records, list) and records:
                html += f"<h3>{record_type}</h3>"
                for record in records:
                    html += f'<span class="list-item">{record}</span> '
                html += "<br><br>"
        
        html += "</div>"
        return html
    
    def _generate_web_tech_section(self, tech_data: Dict) -> str:
        """Génère la section technologies web"""
        html = """
        <div class="section">
            <h2>💻 Technologies Web</h2>
        """
        
        categories = {
            'frameworks': 'Frameworks',
            'servers': 'Serveurs Web',
            'cdn': 'CDN',
            'analytics': 'Analytics',
            'cms': 'CMS'
        }
        
        for key, label in categories.items():
            if key in tech_data and tech_data[key]:
                html += f"<h3>{label}</h3>"
                for tech in tech_data[key]:
                    html += f'<span class="list-item">{tech}</span> '
                html += "<br><br>"
        
        html += "</div>"
        return html
    
    def _generate_security_section(self, security_data: Dict) -> str:
        """Génère la section sécurité"""
        html = """
        <div class="section">
            <h2>🔒 Analyse de Sécurité</h2>
        """
        
        if 'headers' in security_data:
            html += "<h3>Headers de Sécurité</h3><table>"
            html += "<tr><th>Header</th><th>Présent</th><th>Valeur</th></tr>"
            
            for header, info in security_data['headers'].items():
                present = "✅" if info['present'] else "❌"
                value = info.get('value', 'N/A')
                html += f"<tr><td>{header}</td><td>{present}</td><td>{value}</td></tr>"
            
            html += "</table>"
        
        html += "</div>"
        return html
    
    def _generate_geo_section(self, geo_data: Dict) -> str:
        """Génère la section géolocalisation"""
        html = """
        <div class="section">
            <h2>🌍 Géolocalisation</h2>
        """
        
        if 'geolocation' in geo_data:
            for geo_info in geo_data['geolocation']:
                if geo_info.get('country'):
                    html += f"""
                    <div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                        <strong>IP:</strong> {geo_info.get('ip', 'N/A')}<br>
                        <strong>Pays:</strong> {geo_info.get('country', 'N/A')}<br>
                        <strong>Région:</strong> {geo_info.get('region', 'N/A')}<br>
                        <strong>Ville:</strong> {geo_info.get('city', 'N/A')}<br>
                        <strong>Organisation:</strong> {geo_info.get('organization', 'N/A')}
                    </div>
                    """
        
        html += "</div>"
        return html
    
    def _generate_reputation_section(self, reputation_data: Dict) -> str:
        """Génère la section réputation"""
        html = """
        <div class="section">
            <h2>🛡️ Analyse de Réputation</h2>
        """
        
        if 'virustotal' in reputation_data:
            vt_data = reputation_data['virustotal']
            if 'scan_results' in vt_data and vt_data['scan_results']:
                results = vt_data['scan_results']
                html += f"""
                <h3>VirusTotal</h3>
                <p>Malveillant: {results.get('malicious', 0)}</p>
                <p>Suspect: {results.get('suspicious', 0)}</p>
                <p>Propre: {results.get('clean', 0)}</p>
                """
        
        html += "</div>"
        return html
    
    def _generate_scores_section(self, analysis: Dict) -> str:
        """Génère la section des scores"""
        html = """
        <div class="section">
            <h2>📊 Scores d'Évaluation</h2>
        """
        
        if 'trust_score' in analysis:
            trust = analysis['trust_score']
            score_class = 'high' if trust['score'] >= 80 else 'medium' if trust['score'] >= 60 else 'low'
            html += f"""
            <h3>Score de Confiance</h3>
            <span class="score {score_class}">{trust['score']}/100 ({trust['level']})</span>
            """
        
        if 'security_score' in analysis:
            security = analysis['security_score']
            score_class = 'high' if security['score'] >= 80 else 'medium' if security['score'] >= 60 else 'low'
            html += f"""
            <h3>Score de Sécurité</h3>
            <span class="score {score_class}">{security['score']}/100 ({security['level']})</span>
            """
        
        html += "</div>"
        return html
    
    def generate_comparative_report(self, results_list: List[Dict], filename: str) -> bool:
        """Génère un rapport comparatif pour plusieurs domaines"""
        try:
            filepath = REPORTS_DIR / filename
            
            # Créer un rapport CSV comparatif
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # En-têtes
                headers = ['Domain', 'Trust Score', 'Security Score', 'Registrar', 'Creation Date', 
                          'SSL Valid', 'Technologies', 'Country', 'Subdomains Count']
                writer.writerow(headers)
                
                for result in results_list:
                    domain = result.get('domain', 'Unknown')
                    analysis = result.get('analysis', {})
                    
                    # Extraire les données importantes
                    trust_score = analysis.get('trust_score', {}).get('score', 'N/A')
                    security_score = analysis.get('security_score', {}).get('score', 'N/A')
                    registrar = analysis.get('whois', {}).get('registrar', 'N/A')
                    creation_date = analysis.get('whois', {}).get('creation_date', 'N/A')
                    ssl_valid = analysis.get('ssl', {}).get('valid', 'N/A')
                    
                    # Technologies (joindre en une chaîne)
                    tech_data = analysis.get('web_technologies', {})
                    technologies = []
                    for tech_list in tech_data.values():
                        if isinstance(tech_list, list):
                            technologies.extend(tech_list)
                    tech_string = ', '.join(technologies[:5])  # Limiter à 5
                    
                    # Pays
                    geo_data = analysis.get('geolocation', {}).get('geolocation', [])
                    country = geo_data[0].get('country', 'N/A') if geo_data else 'N/A'
                    
                    # Nombre de sous-domaines
                    subdomains_count = len(analysis.get('subdomains', []))
                    
                    writer.writerow([
                        domain, trust_score, security_score, registrar, creation_date,
                        ssl_valid, tech_string, country, subdomains_count
                    ])
            
            return True
        except Exception as e:
            print_error(f"Erreur génération rapport comparatif: {str(e)}")
            return False