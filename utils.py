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
from typing import Dict, List, Optional, Any

# Import des modules d'analyse
from analyzers.web_analyzer import WebAnalyzer
from analyzers.geo_analyzer import GeoAnalyzer
from analyzers.reputation_analyzer import ReputationAnalyzer
from analyzers.monitoring import MonitoringSystem
from exporters.report_generator import ReportGenerator
from core.cache import cache
from core.display import (print_banner, print_section, print_success, 
                         print_error, print_warning, print_info)
from colorama import Fore, Style

def show_interactive_menu():
    """Affiche le menu interactif principal"""
    while True:
        # Effacer l'écran pour une meilleure expérience
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Bannière principale
        print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🔍 NETTRACE v2.0                                  ║
║                    Outil OSINT d'analyse de domaines                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  {Fore.GREEN}✨ Analyse complète • Sécurité • Réputation • Géolocalisation{Fore.CYAN}     ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        # Statistiques du cache
        cache_stats = cache.get_stats()
        print(f"{Fore.BLUE}📊 Cache: {cache_stats['files']} fichiers • {cache_stats['total_size_mb']} MB{Style.RESET_ALL}")
        
        # Menu principal avec design moderne
        print(f"""
{Fore.YELLOW}{Style.BRIGHT}
┌─────────────────────────────────────────────────────────────────────────────┐
│                              🎯 ANALYSES                                    │
├─────────────────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.GREEN}1{Fore.WHITE}. 🔍 Analyse rapide        │ WHOIS + DNS + Technologies web          │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.GREEN}2{Fore.WHITE}. 🎯 Analyse standard      │ + Sécurité + Réputation basique         │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.GREEN}3{Fore.WHITE}. 🚀 Analyse complète      │ + Géolocalisation + Monitoring           │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.GREEN}4{Fore.WHITE}. 📊 Rapport automatique   │ Analyse + Export HTML/JSON               │{Style.RESET_ALL}
{Fore.YELLOW}{Style.BRIGHT}├─────────────────────────────────────────────────────────────────────────────┤
│                              📋 OUTILS                                     │
├─────────────────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.CYAN}5{Fore.WHITE}. 📁 Analyse en lot        │ Traiter plusieurs domaines              │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.CYAN}6{Fore.WHITE}. 🔄 Monitoring            │ Surveillance continue des changements   │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.CYAN}7{Fore.WHITE}. 📈 Rapports comparatifs  │ Comparer plusieurs domaines             │{Style.RESET_ALL}
{Fore.YELLOW}{Style.BRIGHT}├─────────────────────────────────────────────────────────────────────────────┤
│                            ⚙️  CONFIGURATION                               │
├─────────────────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.MAGENTA}8{Fore.WHITE}. 🛠️  Système & Dépendances │ Vérifier installation et outils         │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.MAGENTA}9{Fore.WHITE}. 💾 Gestion du cache     │ Statistiques, nettoyage, configuration  │{Style.RESET_ALL}
{Fore.YELLOW}{Style.BRIGHT}├─────────────────────────────────────────────────────────────────────────────┤
│                              📖 AIDE                                       │
├─────────────────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.YELLOW}h{Fore.WHITE}. ❓ Aide & Documentation  │ Guide d'utilisation et exemples         │{Style.RESET_ALL}
{Fore.WHITE}│ {Fore.YELLOW}e{Fore.WHITE}. 🔍 Exemples pratiques   │ Cas d'usage et démonstrations           │{Style.RESET_ALL}
{Fore.YELLOW}{Style.BRIGHT}└─────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}

{Fore.RED}│ {Fore.RED}q{Fore.WHITE}. 🚪 Quitter{Style.RESET_ALL}
""")
        
        # Prompt amélioré
        print(f"{Fore.GREEN}{Style.BRIGHT}┌─ Votre choix ─────────────────────────────────────────────────────────────┐{Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}│ {Style.BRIGHT}➤{Style.RESET_ALL} ").strip().lower()
        print(f"{Fore.GREEN}{Style.BRIGHT}└───────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        
        if choice == "1":
            handle_quick_analysis()
        elif choice == "2":
            handle_standard_analysis()
        elif choice == "3":
            handle_complete_analysis()
        elif choice == "4":
            handle_report_generation()
        elif choice == "5":
            handle_batch_analysis()
        elif choice == "6":
            handle_monitoring_menu()
        elif choice == "7":
            handle_comparative_analysis()
        elif choice == "8":
            handle_system_config()
        elif choice == "9":
            handle_cache_management()
        elif choice == "h":
            show_help()
        elif choice == "e":
            show_examples()
        elif choice == "q":
            print(f"\n{Fore.CYAN}{Style.BRIGHT}👋 Merci d'avoir utilisé NetTrace!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}🔍 Pour plus d'infos: https://github.com/nettrace{Style.RESET_ALL}\n")
            print_success("\n👋 Merci d'avoir utilisé NetTrace!")
            break
        else:
            print_error("❌ Choix invalide. Utilisez les numéros/lettres du menu.")
            input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_quick_analysis():
    """Gère l'analyse rapide"""
    from nettrace import run_analysis
    
    print_section("🔍 Analyse rapide")
    print_info("Cette analyse inclut : WHOIS + DNS + Sous-domaines + Technologies web")
    
    domain = input(f"{Fore.GREEN}Entrez le domaine à analyser: {Style.RESET_ALL}").strip()
    
    if not domain:
        print_error("❌ Aucun domaine spécifié.")
        return
    
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    print_info(f"\n🚀 Lancement de l'analyse rapide pour: {domain}")
    run_analysis(domain, verbose=verbose, analysis_type="quick")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_standard_analysis():
    """Gère l'analyse standard"""
    from nettrace import run_analysis
    
    print_section("🎯 Analyse standard")
    print_info("Cette analyse inclut : Analyse rapide + Sécurité + Réputation basique")
    
    domain = input(f"{Fore.GREEN}Entrez le domaine à analyser: {Style.RESET_ALL}").strip()
    
    if not domain:
        print_error("❌ Aucun domaine spécifié.")
        return
    
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    print_info(f"\n🚀 Lancement de l'analyse standard pour: {domain}")
    run_analysis(domain, verbose=verbose, analysis_type="standard")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_complete_analysis():
    """Gère l'analyse complète"""
    from nettrace import run_analysis
    
    print_section("🚀 Analyse complète")
    print_info("Cette analyse inclut : Tout + Géolocalisation + Réputation avancée + Monitoring")
    
    domain = input(f"{Fore.GREEN}Entrez le domaine à analyser: {Style.RESET_ALL}").strip()
    
    if not domain:
        print_error("❌ Aucun domaine spécifié.")
        return
    
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    print_info(f"\n🚀 Lancement de l'analyse complète pour: {domain}")
    run_analysis(domain, verbose=verbose, analysis_type="complete")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_monitoring_menu():
    """Gère le menu de monitoring"""
    print_section("🔄 Monitoring des domaines")
    
    monitoring = MonitoringSystem(verbose=True)
    status = monitoring.get_monitoring_status()
    
    print_info(f"📊 Domaines surveillés: {status['total_domains']}")
    print_info(f"🚨 Alertes actives: {status['active_alerts']}")
    
    print_info("\nOptions disponibles:")
    print_info("1. Ajouter un domaine au monitoring")
    print_info("2. Voir les domaines surveillés")
    print_info("3. Supprimer un domaine du monitoring")
    print_info("4. Retour au menu principal")
    
    choice = input(f"\n{Fore.YELLOW}Votre choix (1-4): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        domain = input(f"{Fore.GREEN}Domaine à surveiller: {Style.RESET_ALL}").strip()
        if domain:
            if monitoring.add_domain_monitoring(domain):
                print_success(f"✅ Domaine {domain} ajouté au monitoring")
            else:
                print_warning(f"⚠️  Domaine {domain} déjà surveillé")
    
    elif choice == "2":
        domains = monitoring.monitoring_data.get('domains', {})
        if domains:
            print_info("📋 Domaines surveillés:")
            for domain, data in domains.items():
                last_check = data.get('last_check', 'Jamais')
                alerts_count = len(data.get('alerts', []))
                print_info(f"   • {domain} - Dernière vérif: {last_check} - Alertes: {alerts_count}")
        else:
            print_info("Aucun domaine surveillé")
    
    elif choice == "3":
        domain = input(f"{Fore.GREEN}Domaine à supprimer: {Style.RESET_ALL}").strip()
        if domain and monitoring.remove_domain_monitoring(domain):
            print_success(f"✅ Domaine {domain} supprimé du monitoring")
        else:
            print_error("❌ Domaine non trouvé")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_comparative_analysis():
    """Gère l'analyse comparative"""
    print_section("📈 Analyse comparative")
    
    print_info("Entrez les domaines à comparer (un par ligne, ligne vide pour terminer):")
    domains = []
    
    while True:
        domain = input(f"{Fore.GREEN}Domaine {len(domains)+1}: {Style.RESET_ALL}").strip()
        if not domain:
            break
        domains.append(domain)
        if len(domains) >= 10:  # Limiter à 10 domaines
            print_warning("⚠️  Maximum 10 domaines pour la comparaison")
            break
    
    if len(domains) < 2:
        print_error("❌ Il faut au moins 2 domaines pour une comparaison")
        return
    
    print_info(f"\n🚀 Analyse comparative de {len(domains)} domaines...")
    
    # Analyser chaque domaine
    results = []
    for i, domain in enumerate(domains, 1):
        print_info(f"[{i}/{len(domains)}] Analyse de {domain}...")
        analyzer = DomainAnalyzer(domain, verbose=False)
        result = analyzer.run_standard_analysis()
        results.append(result)
        time.sleep(1)  # Pause entre analyses
    
    # Générer rapport comparatif
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"comparative_analysis_{timestamp}.csv"
    
    report_gen = ReportGenerator()
    if report_gen.generate_comparative_report(results, filename):
        print_success(f"✅ Rapport comparatif sauvegardé: {filename}")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_cache_management():
    """Gère la gestion du cache"""
    print_section("💾 Gestion du cache")
    
    stats = cache.get_stats()
    
    print_info(f"📊 Statistiques du cache:")
    print_info(f"   • Fichiers: {stats['files']}")
    print_info(f"   • Taille totale: {stats['total_size_mb']} MB")
    print_info(f"   • Statut: {'Activé' if stats['enabled'] else 'Désactivé'}")
    
    print_info("\nActions disponibles:")
    print_info("1. Vider tout le cache")
    print_info("2. Vider le cache DNS")
    print_info("3. Vider le cache WHOIS")
    print_info("4. Vider le cache de réputation")
    print_info("5. Retour au menu principal")
    
    choice = input(f"\n{Fore.YELLOW}Votre choix (1-5): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        cache.clear()
        print_success("✅ Cache entièrement vidé")
    elif choice == "2":
        cache.clear('dns')
        print_success("✅ Cache DNS vidé")
    elif choice == "3":
        cache.clear('whois')
        print_success("✅ Cache WHOIS vidé")
    elif choice == "4":
        cache.clear('reputation')
        print_success("✅ Cache de réputation vidé")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def show_examples():
    """Affiche des exemples pratiques"""
    print_section("🔍 Exemples pratiques")
    
    examples = [
        ("Analyse d'un site e-commerce", "amazon.com", "Vérifier la sécurité et les technologies"),
        ("Vérification d'un site suspect", "exemple-suspect.com", "Analyser la réputation et l'âge"),
        ("Audit de sécurité", "monsite.com", "Vérifier les headers et certificats SSL"),
        ("Reconnaissance passive", "entreprise.com", "Découvrir l'infrastructure et sous-domaines"),
        ("Analyse comparative", "site1.com vs site2.com", "Comparer deux concurrents")
    ]
    
    print_info("📋 Cas d'usage courants:")
    for i, (title, domain, desc) in enumerate(examples, 1):
        print_info(f"\n{i}. {Fore.YELLOW}{title}{Style.RESET_ALL}")
        print_info(f"   Domaine: {Fore.GREEN}{domain}{Style.RESET_ALL}")
        print_info(f"   Objectif: {desc}")
    
    print_info(f"\n{Fore.CYAN}💡 Conseils d'utilisation:{Style.RESET_ALL}")
    print_info("• Utilisez l'analyse rapide pour un premier aperçu")
    print_info("• L'analyse complète pour une investigation approfondie")
    print_info("• Le monitoring pour surveiller les changements")
    print_info("• Les rapports HTML pour partager les résultats")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_single_analysis():
    """Gère l'analyse simple d'un domaine"""
    from nettrace import run_analysis
    
    print_section("Analyse simple")
    domain = input(f"{Fore.GREEN}Entrez le domaine à analyser: {Style.RESET_ALL}").strip()
    
    if not domain:
        print_error("❌ Aucun domaine spécifié.")
        return
    
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    # Options d'analyse avancée
    print_info("\n🔧 Options d'analyse:")
    print_info("1. Analyse standard")
    print_info("2. Analyse complète (recommandé)")
    print_info("3. Analyse rapide (sans réputation)")
    
    analysis_type = input(f"{Fore.YELLOW}Type d'analyse (1-3, défaut: 2): {Style.RESET_ALL}").strip() or "2"
    
    print_info(f"\n🚀 Lancement de l'analyse pour: {domain}")
    
    if analysis_type == "1":
        run_analysis(domain, verbose=verbose, analysis_type="standard")
    elif analysis_type == "3":
        run_analysis(domain, verbose=verbose, analysis_type="quick")
    else:
        run_analysis(domain, verbose=verbose, analysis_type="complete")
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_report_generation():
    """Gère la génération de rapport automatique"""
    from nettrace import run_analysis
    
    print_section("Génération de rapport")
    domain = input(f"{Fore.GREEN}Entrez le domaine à analyser: {Style.RESET_ALL}").strip()
    
    if not domain:
        print_error("❌ Aucun domaine spécifié.")
        return
    
    # Choix du format
    print_info("\nFormats disponibles:")
    print_info("1. JSON (recommandé)")
    print_info("2. TXT (lisible)")
    print_info("3. Les deux")
    
    format_choice = input(f"{Fore.YELLOW}Choix du format (1-3): {Style.RESET_ALL}").strip()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"nettrace_{domain.replace('.', '_')}_{timestamp}"
    
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    if format_choice == "1":
        filename = f"{base_filename}.json"
        run_analysis(domain, output=filename, format_type='json', verbose=verbose)
    elif format_choice == "2":
        filename = f"{base_filename}.txt"
        run_analysis(domain, output=filename, format_type='txt', verbose=verbose)
    elif format_choice == "3":
        json_file = f"{base_filename}.json"
        txt_file = f"{base_filename}.txt"
        
        analyzer = DomainAnalyzer(domain, verbose=verbose)
        results = analyzer.run_full_analysis()
        analyzer.display_results(results)
        
        analyzer.export_results(results, json_file, 'json')
        analyzer.export_results(results, txt_file, 'txt')
        
        print_success(f"✅ Rapports sauvegardés:")
        print_success(f"   📄 {json_file}")
        print_success(f"   📄 {txt_file}")
    else:
        print_error("❌ Choix invalide.")
        return
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_batch_analysis():
    """Gère l'analyse en lot de plusieurs domaines"""
    from nettrace import run_analysis
    
    print_section("Analyse en lot")
    
    print_info("Options d'entrée:")
    print_info("1. Saisie manuelle")
    print_info("2. Fichier texte")
    
    input_choice = input(f"{Fore.YELLOW}Choix (1-2): {Style.RESET_ALL}").strip()
    
    domains = []
    
    if input_choice == "1":
        print_info("\nEntrez les domaines (un par ligne, ligne vide pour terminer):")
        while True:
            domain = input(f"{Fore.GREEN}Domaine: {Style.RESET_ALL}").strip()
            if not domain:
                break
            domains.append(domain)
    
    elif input_choice == "2":
        filename = input(f"{Fore.GREEN}Nom du fichier: {Style.RESET_ALL}").strip()
        try:
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print_error(f"❌ Fichier '{filename}' introuvable.")
            return
        except Exception as e:
            print_error(f"❌ Erreur lecture fichier: {str(e)}")
            return
    else:
        print_error("❌ Choix invalide.")
        return
    
    if not domains:
        print_error("❌ Aucun domaine à analyser.")
        return
    
    # Options d'export
    export_individual = input(f"{Fore.YELLOW}Générer des rapports individuels? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    verbose = input(f"{Fore.YELLOW}Mode verbeux? (o/N): {Style.RESET_ALL}").strip().lower() == 'o'
    
    print_info(f"\n🚀 Analyse de {len(domains)} domaine(s)...")
    
    success_count = 0
    for i, domain in enumerate(domains, 1):
        print_info(f"\n[{i}/{len(domains)}] Analyse de: {domain}")
        
        try:
            if export_individual:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"nettrace_{domain.replace('.', '_')}_{timestamp}.json"
                success = run_analysis(domain, output=filename, verbose=verbose)
            else:
                success = run_analysis(domain, verbose=verbose)
            
            if success:
                success_count += 1
            
            # Pause entre analyses
            if i < len(domains):
                time.sleep(2)
                
        except KeyboardInterrupt:
            print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
            break
    
    print_info(f"\n📊 Résultats: {success_count}/{len(domains)} analyses réussies")
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def handle_system_config():
    """Affiche la configuration système"""
    print_section("Configuration système")
    
    # Vérification des modules Python
    print_info("🐍 Modules Python:")
    modules = ['whois', 'dns.resolver', 'requests', 'colorama', 'dateutil']
    
    for module in modules:
        try:
            __import__(module)
            print_success(f"   ✅ {module}")
        except ImportError:
            print_error(f"   ❌ {module} (pip install {module})")
    
    # Vérification des outils externes
    print_info("\n🛠️  Outils externes:")
    tools = ['subfinder', 'amass']
    
    for tool in tools:
        try:
            result = subprocess.run([tool, '--version'], capture_output=True, timeout=5)
            if result.returncode == 0:
                print_success(f"   ✅ {tool}")
            else:
                print_warning(f"   ⚠️  {tool} (installé mais erreur)")
        except FileNotFoundError:
            print_warning(f"   ❌ {tool} (optionnel)")
        except subprocess.TimeoutExpired:
            print_warning(f"   ⚠️  {tool} (timeout)")
        except Exception:
            print_warning(f"   ❓ {tool} (statut inconnu)")
    
    # Vérification du cache
    print_info("\n💾 Cache:")
    cache_stats = cache.get_stats()
    print_info(f"   📁 Fichiers en cache: {cache_stats['files']}")
    print_info(f"   💽 Taille totale: {cache_stats['total_size_mb']} MB")
    print_info(f"   ⚙️  Statut: {'Activé' if cache_stats['enabled'] else 'Désactivé'}")
    
    # Configuration des APIs
    print_info("\n🔑 APIs configurées:")
    from config.settings import API_KEYS
    
    for api_name, api_key in API_KEYS.items():
        if api_key:
            print_success(f"   ✅ {api_name.upper()}")
        else:
            print_warning(f"   ❌ {api_name.upper()} (non configurée)")
    
    # Informations système
    print_info("\n💻 Système:")
    import platform
    print_info(f"   OS: {platform.system()} {platform.release()}")
    print_info(f"   Python: {platform.python_version()}")
    
    # Actions disponibles
    print_info("\n🔧 Actions disponibles:")
    print_info("1. Vider le cache")
    print_info("2. Test de connectivité")
    print_info("3. Retour au menu")
    
    action = input(f"\n{Fore.YELLOW}Action (1-3): {Style.RESET_ALL}").strip()
    
    if action == "1":
        cache.clear()
        print_success("✅ Cache vidé avec succès")
    elif action == "2":
        print_info("🔄 Test de connectivité...")
        test_connectivity()
    
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

def test_connectivity():
    """Test la connectivité vers les services externes"""
    services = [
        ("Google DNS", "8.8.8.8", 53),
        ("Cloudflare DNS", "1.1.1.1", 53),
        ("crt.sh", "crt.sh", 443),
        ("VirusTotal", "www.virustotal.com", 443)
    ]
    
    for name, host, port in services:
        try:
            import socket
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            print_success(f"   ✅ {name}")
        except Exception:
            print_error(f"   ❌ {name}")

def show_help():
    """Affiche l'aide détaillée"""
    print_section("Aide - NetTrace")
    
    help_text = f"""
{Fore.CYAN}🎯 OBJECTIF{Style.RESET_ALL}
NetTrace est un outil OSINT pour analyser des domaines sans APIs payantes.

{Fore.CYAN}🔍 FONCTIONNALITÉS{Style.RESET_ALL}
• WHOIS lookup (registrar, dates, propriétaire)
• Résolution DNS complète (A, AAAA, MX, TXT, NS)
• Extraction de sous-domaines (crt.sh, subfinder, amass)
• Score de confiance intelligent (0-100)
• Export en JSON/TXT
• Lien VirusTotal automatique

{Fore.CYAN}📊 SCORE DE CONFIANCE{Style.RESET_ALL}
• 80-100: Domaine établi et fiable
• 60-79:  Domaine standard
• 0-59:   Domaine récent ou suspect

{Fore.CYAN}💡 CONSEILS{Style.RESET_ALL}
• Installez subfinder/amass pour plus de sous-domaines
• Utilisez le mode verbeux pour le débogage
• Les rapports JSON sont plus complets que TXT

{Fore.CYAN}⚖️  ÉTHIQUE{Style.RESET_ALL}
• Reconnaissance passive uniquement
• Respect des sources publiques
• Usage responsable et légal
    """
    
    print(help_text)
    input(f"\n{Fore.CYAN}Appuyez sur Entrée pour continuer...{Style.RESET_ALL}")

class DomainAnalyzer:
    """Classe principale pour l'analyse OSINT de domaines"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {}
        
        # Initialiser les analyseurs spécialisés
        self.web_analyzer = WebAnalyzer(domain, verbose)
        self.geo_analyzer = GeoAnalyzer(domain, verbose)
        self.reputation_analyzer = ReputationAnalyzer(domain, verbose)
        self.report_generator = ReportGenerator(verbose)
        
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
        
        print_info("🚀 Lancement de l'analyse complète...")
        print_info("=" * 60)
        
        # 1. WHOIS
        print_info("🔄 Étape 1/9: Recherche WHOIS...")
        results['analysis']['whois'] = self.whois_lookup()
        time.sleep(1)
        
        # 2. DNS
        print_info("\n🔄 Étape 2/9: Résolution DNS...")
        results['analysis']['dns'] = self.dns_resolution()
        time.sleep(1)
        
        # 3. Sous-domaines
        print_info("\n🔄 Étape 3/9: Recherche de sous-domaines...")
        results['analysis']['subdomains'] = self.find_subdomains()
        time.sleep(1)
        
        # 4. Technologies web
        print_info("\n🔄 Étape 4/9: Analyse des technologies web...")
        results['analysis']['web_technologies'] = self.web_analyzer.analyze_technologies()
        time.sleep(1)
        
        # 5. Analyse de sécurité
        print_info("\n🔄 Étape 5/9: Analyse de sécurité...")
        results['analysis']['security'] = {
            'headers': self.web_analyzer.analyze_security_headers(),
            'ssl': self.web_analyzer.analyze_ssl_certificate(),
            'common_files': self.web_analyzer.check_common_files(),
            'redirects': self.web_analyzer.analyze_redirects()
        }
        time.sleep(1)
        
        # 6. Analyse géographique
        print_info("\n🔄 Étape 6/9: Analyse géographique...")
        results['analysis']['geolocation'] = self.geo_analyzer.analyze_hosting_infrastructure()
        results['analysis']['latency'] = self.geo_analyzer.analyze_latency()
        time.sleep(1)
        
        # 7. Analyse de réputation
        print_info("\n🔄 Étape 7/9: Analyse de réputation...")
        vt_results = self.reputation_analyzer.check_virustotal()
        malware_results = self.reputation_analyzer.check_malware_domains()
        phishtank_results = self.reputation_analyzer.check_phishtank()
        ct_results = self.reputation_analyzer.check_certificate_transparency()
        
        results['analysis']['reputation'] = {
            'virustotal': vt_results,
            'malware_check': malware_results,
            'phishtank': phishtank_results,
            'certificate_transparency': ct_results,
            'virustotal_link': self.virustotal_link()
        }
        time.sleep(1)
        
        # 8. Calcul des scores
        print_info("\n🔄 Étape 8/9: Calcul des scores...")
        results['analysis']['trust_score'] = self.calculate_trust_score(
            results['analysis']['whois'],
            results['analysis']['dns'],
            results['analysis']['subdomains']
        )
        results['analysis']['security_score'] = self.calculate_security_score(results['analysis']['security'])
        results['analysis']['reputation_score'] = self.reputation_analyzer.calculate_reputation_score(
            vt_results, malware_results, phishtank_results, ct_results
        )
        time.sleep(1)
        
        # 9. Finalisation
        print_info("\n🔄 Étape 9/9: Finalisation du rapport...")
        time.sleep(1)
        
        return results
    
    def run_quick_analysis(self):
        """Lance une analyse rapide (sans réputation)"""
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        print_info("🚀 Lancement de l'analyse rapide...")
        print_info("=" * 60)
        
        # 1. WHOIS
        print_info("🔄 Étape 1/5: Recherche WHOIS...")
        results['analysis']['whois'] = self.whois_lookup()
        time.sleep(0.5)
        
        # 2. DNS
        print_info("\n🔄 Étape 2/5: Résolution DNS...")
        results['analysis']['dns'] = self.dns_resolution()
        time.sleep(0.5)
        
        # 3. Sous-domaines (limité)
        print_info("\n🔄 Étape 3/5: Recherche de sous-domaines (rapide)...")
        results['analysis']['subdomains'] = self.find_subdomains_quick()
        time.sleep(0.5)
        
        # 4. Technologies web basiques
        print_info("\n🔄 Étape 4/5: Analyse des technologies web...")
        results['analysis']['web_technologies'] = self.web_analyzer.analyze_technologies()
        time.sleep(0.5)
        
        # 5. Score de confiance
        print_info("\n🔄 Étape 5/5: Calcul du score de confiance...")
        results['analysis']['trust_score'] = self.calculate_trust_score(
            results['analysis']['whois'],
            results['analysis']['dns'],
            results['analysis']['subdomains']
        )
        
        # Lien VirusTotal seulement
        results['analysis']['reputation'] = {
            'virustotal_link': self.virustotal_link()
        }
        
        return results
    
    def run_standard_analysis(self):
        """Lance une analyse standard (sans géolocalisation avancée)"""
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        print_info("🚀 Lancement de l'analyse standard...")
        print_info("=" * 60)
        
        # 1-3. Base
        print_info("🔄 Étape 1/7: Recherche WHOIS...")
        results['analysis']['whois'] = self.whois_lookup()
        time.sleep(0.5)
        
        print_info("\n🔄 Étape 2/7: Résolution DNS...")
        results['analysis']['dns'] = self.dns_resolution()
        time.sleep(0.5)
        
        print_info("\n🔄 Étape 3/7: Recherche de sous-domaines...")
        results['analysis']['subdomains'] = self.find_subdomains()
        time.sleep(0.5)
        
        # 4. Technologies
        print_info("\n🔄 Étape 4/7: Analyse des technologies web...")
        results['analysis']['web_technologies'] = self.web_analyzer.analyze_technologies()
        time.sleep(0.5)
        
        # 5. Sécurité
        print_info("\n🔄 Étape 5/7: Analyse de sécurité...")
        results['analysis']['security'] = {
            'headers': self.web_analyzer.analyze_security_headers(),
            'ssl': self.web_analyzer.analyze_ssl_certificate(),
            'redirects': self.web_analyzer.analyze_redirects()
        }
        time.sleep(0.5)
        
        # 6. Réputation basique
        print_info("\n🔄 Étape 6/7: Vérification réputation...")
        vt_results = self.reputation_analyzer.check_virustotal()
        results['analysis']['reputation'] = {
            'virustotal': vt_results,
            'virustotal_link': self.virustotal_link()
        }
        time.sleep(0.5)
        
        # 7. Scores
        print_info("\n🔄 Étape 7/7: Calcul des scores...")
        results['analysis']['trust_score'] = self.calculate_trust_score(
            results['analysis']['whois'],
            results['analysis']['dns'],
            results['analysis']['subdomains']
        )
        results['analysis']['security_score'] = self.calculate_security_score(results['analysis']['security'])
        
        return results
    
    def find_subdomains_quick(self):
        """Recherche rapide de sous-domaines (crt.sh seulement)"""
        print_section("Extraction de sous-domaines (rapide)")
        subdomains = set()
        
        # Recherche via crt.sh uniquement
        try:
            self.log_verbose("Recherche via crt.sh")
            url = f"https://crt.sh/?q={self.domain}&output=json"
            response = requests.get(url, timeout=10)  # Timeout réduit
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[:100]:  # Limiter à 100 entrées
                    name = entry['name_value']
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            subdomains.add(subdomain)
                
                print_success(f"✅ crt.sh: {len(subdomains)} sous-domaines trouvés")
            else:
                print_warning("⚠️  crt.sh: Aucune réponse")
                
        except Exception as e:
            print_error(f"❌ Erreur crt.sh: {str(e)}")
        
        # Nettoyage
        clean_subdomains = []
        for sub in sorted(subdomains):
            if sub and '.' in sub and not sub.startswith('*'):
                clean_subdomains.append(sub)
        
        print_info(f"🎯 Total: {len(clean_subdomains)} sous-domaines")
        return clean_subdomains[:50]  # Limiter à 50
    
    def calculate_security_score(self, security_data: Dict) -> Dict:
        """Calcule un score de sécurité"""
        print_section("Score de sécurité")
        score = 0
        details = []
        max_score = 100
        
        # Headers de sécurité (40 points max)
        if 'headers' in security_data and 'score' in security_data['headers']:
            header_score = security_data['headers']['score']
            max_header_score = security_data['headers']['max_score']
            normalized_score = int((header_score / max_header_score) * 40) if max_header_score > 0 else 0
            score += normalized_score
            details.append(f"🔒 Headers de sécurité: +{normalized_score} pts")
        
        # Certificat SSL (30 points max)
        if 'ssl' in security_data and 'score' in security_data['ssl']:
            ssl_score = min(security_data['ssl']['score'], 30)
            score += ssl_score
            details.append(f"🔐 Certificat SSL: +{ssl_score} pts")
        
        # Redirections HTTPS (15 points)
        if 'redirects' in security_data:
            redirects = security_data['redirects']
            if redirects.get('http_to_https'):
                score += 15
                details.append("🔄 Redirection HTTPS: +15 pts")
            else:
                details.append("🔄 Pas de redirection HTTPS: +0 pts")
        
        # Fichiers de sécurité (15 points max)
        if 'common_files' in security_data:
            files = security_data['common_files']
            security_files = ['robots.txt', 'security.txt']
            found_files = sum(1 for f in security_files if files.get(f, {}).get('exists', False))
            file_score = found_files * 7  # 7 points par fichier
            score += file_score
            details.append(f"📄 Fichiers de sécurité: +{file_score} pts")
        
        # Déterminer le niveau
        if score >= 80:
            level = "EXCELLENT"
            color = Fore.GREEN
        elif score >= 60:
            level = "BON"
            color = Fore.YELLOW
        elif score >= 40:
            level = "MOYEN"
            color = Fore.YELLOW
        else:
            level = "FAIBLE"
            color = Fore.RED
        
        print(f"{color}{Style.BRIGHT}🔒 Score de sécurité: {score}/100 ({level}){Style.RESET_ALL}")
        print_info("\n📊 Détails du scoring:")
        for detail in details:
            print_info(f"   {detail}")
        
        return {
            'score': score,
            'level': level,
            'details': details
        }
    
    def display_results(self, results):
        """Affiche un résumé des résultats"""
        print_section("RÉSUMÉ DE L'ANALYSE")
        
        domain = results['domain']
        analysis = results['analysis']
        
        print_info(f"🎯 Domaine analysé: {domain}")
        print_info(f"📅 Date d'analyse: {results['timestamp']}")
        
        print_section("INFORMATIONS GÉNÉRALES")
        
        # Statistiques rapides
        if 'whois' in analysis and 'registrar' in analysis['whois']:
            print_info(f"🏢 Registrar: {analysis['whois']['registrar']}")
        
        if 'whois' in analysis and 'creation_date' in analysis['whois']:
            print_info(f"📅 Date de création: {analysis['whois']['creation_date']}")
        
        if 'dns' in analysis:
            dns_records = sum(1 for records in analysis['dns'].values() if isinstance(records, list) and records)
            print_info(f"🌐 Enregistrements DNS: {dns_records}")
        
        if 'subdomains' in analysis:
            print_info(f"🔍 Sous-domaines trouvés: {len(analysis['subdomains'])}")
        
        print_section("TECHNOLOGIES WEB")
        
        if 'web_technologies' in analysis:
            tech_data = analysis['web_technologies']
            
            if tech_data.get('frameworks'):
                print_info(f"⚛️  Frameworks: {', '.join(tech_data['frameworks'])}")
            
            if tech_data.get('servers'):
                print_info(f"🖥️  Serveurs: {', '.join(tech_data['servers'])}")
            
            if tech_data.get('cdn'):
                print_info(f"🌐 CDN: {', '.join(tech_data['cdn'])}")
            
            if tech_data.get('analytics'):
                print_info(f"📊 Analytics: {', '.join(tech_data['analytics'])}")
        
        print_section("SÉCURITÉ")
        
        if 'security' in analysis:
            security = analysis['security']
            
            if 'ssl' in security and security['ssl'].get('valid'):
                ssl_info = security['ssl']
                issuer = ssl_info.get('issuer', {}).get('organizationName', 'Inconnu')
                print_info(f"🔐 SSL: Certificat valide ({issuer})")
            else:
                print_info("🔐 SSL: Certificat invalide ou absent")
            
            if 'redirects' in security and security['redirects'].get('http_to_https'):
                print_info("✅ HTTPS: Redirection active")
            else:
                print_info("❌ HTTPS: Pas de redirection")
        
        print_section("GÉOLOCALISATION")
        
        if 'geolocation' in analysis and 'countries' in analysis['geolocation']:
            countries = analysis['geolocation']['countries']
            if countries:
                print_info(f"🌍 Pays d'hébergement: {', '.join(countries[:3])}")
        
        if 'geolocation' in analysis and 'hosting_providers' in analysis['geolocation']:
            providers = analysis['geolocation']['hosting_providers']
            if providers:
                unique_providers = list(set(providers))[:3]
                print_info(f"🏢 Fournisseurs: {', '.join(unique_providers)}")
        
        print_section("SCORES D'ÉVALUATION")
        
        if 'trust_score' in analysis:
            score = analysis['trust_score']['score']
            level = analysis['trust_score']['level']
            color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED
            print(f"{color}🎯 Score de confiance: {score}/100 ({level}){Style.RESET_ALL}")
        
        if 'security_score' in analysis:
            score = analysis['security_score']['score']
            level = analysis['security_score']['level']
            color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED
            print(f"{color}🔒 Score de sécurité: {score}/100 ({level}){Style.RESET_ALL}")
        
        if 'reputation_score' in analysis:
            score = analysis['reputation_score']['score']
            level = analysis['reputation_score']['level']
            color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED
            print(f"{color}🛡️  Score de réputation: {score}/100 ({level}){Style.RESET_ALL}")
        if 'reputation' in analysis:
            rep = analysis['reputation']
            
            if 'virustotal' in rep and rep['virustotal'].get('scan_results'):
                vt = rep['virustotal']['scan_results']
                malicious = vt.get('malicious', 0)
                if malicious > 0:
                    print_info(f"⚠️  VirusTotal: {malicious} détections malveillantes")
                else:
                    print_info("✅ VirusTotal: Aucune détection malveillante")
            
            if 'malware_check' in rep and rep['malware_check'].get('blacklisted'):
                sources = rep['malware_check'].get('sources', [])
                print_info(f"❌ Blacklisté sur: {', '.join(sources)}")
            else:
                print_info("✅ Pas de blacklisting détecté")
            
            if 'virustotal_link' in rep:
                print_info(f"🔗 VirusTotal: {rep['virustotal_link']}")
        
        print_section("RÉSUMÉ TECHNIQUE")
        
        # Statistiques techniques
        tech_stats = []
        
        if 'web_technologies' in analysis:
            tech_count = sum(len(techs) for techs in analysis['web_technologies'].values() if isinstance(techs, list))
            tech_stats.append(f"Technologies détectées: {tech_count}")
        
        if 'security' in analysis and 'headers' in analysis['security']:
            headers_present = sum(1 for h in analysis['security']['headers'].values() if h.get('present'))
            tech_stats.append(f"Headers de sécurité: {headers_present}")
        
        if 'latency' in analysis and 'domain_latency' in analysis['latency']:
            latency = analysis['latency']['domain_latency']
            if 'avg' in latency:
                tech_stats.append(f"Latence moyenne: {latency['avg']:.0f}ms")
        
        for stat in tech_stats:
            print_info(f"📊 {stat}")
    
    def export_results(self, results, filename, format_type='json'):
        """Exporte les résultats"""
        try:
            if format_type == 'json':
                success = self.report_generator.generate_json_report(results, filename)
                if success:
                    print_success(f"✅ Rapport JSON sauvegardé: {filename}")
                return success
            
            elif format_type == 'txt':
                # Générer un rapport HTML plus complet pour le format "txt"
                html_filename = filename.replace('.txt', '.html')
                success = self.report_generator.generate_html_report(results, html_filename)
                if success:
                    print_success(f"✅ Rapport HTML sauvegardé: {html_filename}")
                return success
            
            elif format_type == 'csv':
                success = self.report_generator.generate_csv_report(results, filename)
                if success:
                    print_success(f"✅ Rapport CSV sauvegardé: {filename}")
                return success
            
            elif format_type == 'xml':
                success = self.report_generator.generate_xml_report(results, filename)
                if success:
                    print_success(f"✅ Rapport XML sauvegardé: {filename}")
                return success
            
            return True
        except Exception as e:
            print_error(f"❌ Erreur lors de l'export: {str(e)}")
            return False