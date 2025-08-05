#!/usr/bin/env python3
"""
Fonctions d'affichage pour NetTrace
"""

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
{Fore.GREEN}🔍 Outil OSINT d'analyse de domaines {Style.RESET_ALL}
{Fore.BLUE}By: Root3301 | Version: 1.0{Style.RESET_ALL}
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