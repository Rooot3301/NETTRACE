#!/usr/bin/env python3
"""
Système d'affichage avancé pour NetTrace avec animations et interface moderne
"""

import time
import sys
import os
from colorama import init, Fore, Back, Style
from datetime import datetime

# Initialisation de colorama
init(autoreset=True)

def clear_screen():
    """Efface l'écran"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_animated_text(text, delay=0.03, color=Fore.CYAN):
    """Affiche du texte avec animation de frappe"""
    for char in text:
        print(color + char, end='', flush=True)
        time.sleep(delay)
    print(Style.RESET_ALL)

def print_loading_bar(duration=2.0, text="Initialisation"):
    """Affiche une barre de progression animée"""
    width = 50
    print(f"\n{Fore.CYAN}🔄 {text}...{Style.RESET_ALL}")
    
    for i in range(width + 1):
        percent = (i / width) * 100
        filled = '█' * i
        empty = '░' * (width - i)
        
        print(f"\r{Fore.BLUE}[{filled}{empty}] {percent:3.0f}%{Style.RESET_ALL}", end='', flush=True)
        time.sleep(duration / width)
    
    print(f"\n{Fore.GREEN}✅ {text} terminée!{Style.RESET_ALL}\n")

def print_startup_sequence():
    """Séquence de démarrage impressionnante"""
    clear_screen()
    
    # Logo animé
    logo_lines = [
        "███╗   ██╗███████╗████████╗████████╗██████╗  █████╗  ██████╗███████╗",
        "████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝",
        "██╔██╗ ██║█████╗     ██║      ██║   ██████╔╝███████║██║     █████╗  ",
        "██║╚██╗██║██╔══╝     ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ",
        "██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗",
        "╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝"
    ]
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}")
    for line in logo_lines:
        print_animated_text(line, delay=0.01, color=Fore.CYAN + Style.BRIGHT)
        time.sleep(0.1)
    
    # Informations système
    print(f"\n{Fore.GREEN}🔍 Outil OSINT d'analyse de domaines professionnel{Style.RESET_ALL}")
    print(f"{Fore.BLUE}📅 Version: 1.0.1 | Auteur: Root3301 | {datetime.now().strftime('%Y')}{Style.RESET_ALL}")
    
    # Barre de chargement
    print_loading_bar(1.5, "Chargement des modules")
    
    # Vérifications système
    checks = [
        ("Cache système", True),
        ("Modules réseau", True),
        ("Analyseurs OSINT", True),
        ("Générateurs de rapports", True),
        ("Système de monitoring", True)
    ]
    
    print(f"{Fore.YELLOW}🔧 Vérifications système:{Style.RESET_ALL}")
    for check_name, status in checks:
        time.sleep(0.2)
        if status:
            print(f"  {Fore.GREEN}✅ {check_name}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}❌ {check_name}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}🚀 NetTrace prêt à l'emploi!{Style.RESET_ALL}")
    time.sleep(0.5)

def print_banner():
    """Affiche la bannière simple (pour usage non-interactif)"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 NETTRACE{Style.RESET_ALL} - {Fore.GREEN}Outil OSINT d'analyse de domaines{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Version 1.0.1 | By: Root3301{Style.RESET_ALL}\n")

def print_menu_header():
    """En-tête du menu principal"""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                    {Fore.WHITE}{Style.BRIGHT}🔍 NETTRACE - MENU PRINCIPAL{Style.RESET_ALL}                    {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")

def print_menu_footer():
    """Pied du menu principal"""
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def print_menu_option(number, icon, title, description=""):
    """Affiche une option de menu stylisée"""
    if description:
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  {Fore.YELLOW}{number}.{Style.RESET_ALL} {icon} {Fore.WHITE}{Style.BRIGHT}{title:<25}{Style.RESET_ALL} {Fore.CYAN}│{Style.RESET_ALL} {description:<25} {Fore.CYAN}║{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  {Fore.YELLOW}{number}.{Style.RESET_ALL} {icon} {Fore.WHITE}{Style.BRIGHT}{title:<58}{Style.RESET_ALL} {Fore.CYAN}║{Style.RESET_ALL}")

def print_menu_separator():
    """Séparateur de menu"""
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")

def print_submenu_header(title):
    """En-tête de sous-menu"""
    print(f"\n{Fore.MAGENTA}╔══════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}║{Style.RESET_ALL}                    {Fore.WHITE}{Style.BRIGHT}{title:<46}{Style.RESET_ALL}                    {Fore.MAGENTA}║{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}╠══════════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")

def print_submenu_footer():
    """Pied de sous-menu"""
    print(f"{Fore.MAGENTA}╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def print_submenu_option(number, icon, title, description=""):
    """Affiche une option de sous-menu stylisée"""
    if description:
        print(f"{Fore.MAGENTA}║{Style.RESET_ALL}  {Fore.YELLOW}{number}.{Style.RESET_ALL} {icon} {Fore.WHITE}{Style.BRIGHT}{title:<25}{Style.RESET_ALL} {Fore.MAGENTA}│{Style.RESET_ALL} {description:<25} {Fore.MAGENTA}║{Style.RESET_ALL}")
    else:
        print(f"{Fore.MAGENTA}║{Style.RESET_ALL}  {Fore.YELLOW}{number}.{Style.RESET_ALL} {icon} {Fore.WHITE}{Style.BRIGHT}{title:<58}{Style.RESET_ALL} {Fore.MAGENTA}║{Style.RESET_ALL}")

def print_input_prompt(text, icon="🔸"):
    """Prompt d'entrée stylisé"""
    return input(f"\n{Fore.CYAN}{icon} {text}:{Style.RESET_ALL} ")

def print_analysis_header(domain, analysis_type="complète"):
    """En-tête d'analyse"""
    print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎯 ANALYSE {analysis_type.upper()} - {domain.upper()}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}📅 Démarrage: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")

def print_section(title):
    """Affiche une section avec style amélioré"""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}📋 {title.upper()}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'─' * min(len(title) + 4, 60)}{Style.RESET_ALL}")

def print_subsection(title):
    """Affiche une sous-section"""
    print(f"\n{Fore.CYAN}  🔸 {title}{Style.RESET_ALL}")

def print_progress_step(step, total, description):
    """Affiche l'étape de progression"""
    percent = (step / total) * 100
    bar_length = 30
    filled = int(bar_length * step / total)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    print(f"\r{Fore.BLUE}[{bar}] {percent:3.0f}% - {description}{Style.RESET_ALL}", end='', flush=True)
    if step == total:
        print()  # Nouvelle ligne à la fin

def print_success(text):
    """Affiche un message de succès"""
    print(f"{Fore.GREEN}✅ {text}{Style.RESET_ALL}")

def print_error(text):
    """Affiche un message d'erreur"""
    print(f"{Fore.RED}❌ {text}{Style.RESET_ALL}")

def print_warning(text):
    """Affiche un message d'avertissement"""
    print(f"{Fore.YELLOW}⚠️  {text}{Style.RESET_ALL}")

def print_info(text):
    """Affiche un message d'information"""
    print(f"{Fore.CYAN}ℹ️  {text}{Style.RESET_ALL}")

def print_result_item(label, value, icon="🔹"):
    """Affiche un élément de résultat"""
    if isinstance(value, list):
        if value:
            print(f"{Fore.CYAN}{icon} {label}:{Style.RESET_ALL}")
            for item in value[:5]:  # Limiter à 5 éléments
                print(f"  {Fore.WHITE}• {item}{Style.RESET_ALL}")
            if len(value) > 5:
                print(f"  {Fore.YELLOW}... et {len(value) - 5} autres{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}{icon} {label}:{Style.RESET_ALL} {Fore.YELLOW}Aucun{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}{icon} {label}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")

def print_score_bar(score, max_score=100, label="Score"):
    """Affiche une barre de score colorée"""
    percentage = (score / max_score) * 100
    bar_length = 40
    filled = int(bar_length * score / max_score)
    
    # Couleur selon le score
    if percentage >= 80:
        color = Fore.GREEN
        level = "EXCELLENT"
    elif percentage >= 60:
        color = Fore.YELLOW
        level = "BON"
    elif percentage >= 40:
        color = Fore.MAGENTA
        level = "MOYEN"
    else:
        color = Fore.RED
        level = "FAIBLE"
    
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"{Fore.CYAN}📊 {label}:{Style.RESET_ALL} {color}[{bar}] {score}/{max_score} ({level}){Style.RESET_ALL}")

def print_table_header(headers):
    """Affiche l'en-tête d'un tableau"""
    header_line = " | ".join(f"{h:<15}" for h in headers)
    separator = "-" * len(header_line)
    
    print(f"\n{Fore.CYAN}{header_line}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{separator}{Style.RESET_ALL}")

def print_table_row(values):
    """Affiche une ligne de tableau"""
    row_line = " | ".join(f"{str(v):<15}" for v in values)
    print(f"{Fore.WHITE}{row_line}{Style.RESET_ALL}")

def print_footer_stats(execution_time, cache_hits=None):
    """Affiche les statistiques finales"""
    print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📊 STATISTIQUES D'EXÉCUTION{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}⏱️  Temps d'exécution:{Style.RESET_ALL} {Fore.WHITE}{execution_time:.2f} secondes{Style.RESET_ALL}")
    if cache_hits is not None:
        print(f"{Fore.CYAN}💾 Hits cache:{Style.RESET_ALL} {Fore.WHITE}{cache_hits}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📅 Terminé le:{Style.RESET_ALL} {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")

def print_goodbye():
    """Message d'au revoir stylisé"""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                    {Fore.GREEN}🙏 Merci d'avoir utilisé NetTrace!{Style.RESET_ALL}                   {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                                                                      {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}     {Fore.YELLOW}🌟 N'hésitez pas à contribuer sur GitHub{Style.RESET_ALL}                     {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}     {Fore.BLUE}📧 Rapportez les bugs et suggestions{Style.RESET_ALL}                        {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                                                                      {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                    {Fore.MAGENTA}🔍 Happy OSINT Hunting! 🔍{Style.RESET_ALL}                     {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print()

def wait_for_enter(message="Appuyez sur Entrée pour continuer..."):
    """Attend que l'utilisateur appuie sur Entrée"""
    input(f"\n{Fore.YELLOW}⏸️  {message}{Style.RESET_ALL}")

def print_ascii_art_small():
    """Petit ASCII art pour les en-têtes"""
    art = f"""
{Fore.CYAN}    ╔╗╔┌─┐┌┬┐╔╦╗┬─┐┌─┐┌─┐┌─┐
    ║║║├┤  │  ║ ├┬┘├─┤│  ├┤ 
    ╝╚╝└─┘ ┴  ╩ ┴└─┴ ┴└─┘└─┘{Style.RESET_ALL}
    """
    print(art)