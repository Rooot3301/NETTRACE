#!/usr/bin/env python3
"""
NetTrace - Outil OSINT d'analyse de domaines
Auteur: Assistant IA
Version: 1.0

Outil complet d'analyse OSINT pour domaines sans APIs payantes
"""

import argparse
import json
import sys
import time
from datetime import datetime
from utils import DomainAnalyzer, print_banner, print_section, print_success, print_error, print_warning, print_info, show_interactive_menu

def run_analysis(domain, output=None, format_type='json', verbose=False):
    """Lance l'analyse pour un domaine donné"""
    # Validation du domaine
    domain = domain.lower().strip()
    if not domain or '.' not in domain:
        print_error("❌ Domaine invalide. Veuillez spécifier un domaine valide (ex: google.com)")
        return False
    
    print_info(f"🎯 Analyse du domaine: {domain}")
    print_info("=" * 60)
    
    # Initialisation de l'analyseur
    analyzer = DomainAnalyzer(domain, verbose=verbose)
    
    try:
        # Exécution de l'analyse complète
        results = analyzer.run_full_analysis()
        
        # Affichage des résultats
        analyzer.display_results(results)
        
        # Export si demandé
        if output:
            analyzer.export_results(results, output, format_type)
            print_success(f"✅ Rapport sauvegardé: {output}")
        
        print_info("\n" + "=" * 60)
        print_success("🎉 Analyse terminée avec succès!")
        return True
        
    except KeyboardInterrupt:
        print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
        return False
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="NetTrace - Outil OSINT d'analyse de domaines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'usage:
  python nettrace.py --domain google.com
  python nettrace.py --domain example.com --output report.json
  python nettrace.py --domain test.com --format txt --output report.txt
        """
    )
    
    parser.add_argument(
        '--domain', '-d', 
        required=True, 
        help='Domaine à analyser (ex: google.com)'
    )
    
    parser.add_argument(
        '--output', '-o', 
        help='Fichier de sortie pour sauvegarder le rapport'
    )
    
    parser.add_argument(
        '--format', '-f', 
        choices=['json', 'txt'], 
        default='json',
        help='Format de sortie (json ou txt, défaut: json)'
    )
    
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Mode verbeux'
    )
    
    parser.add_argument(
        '--interactive', '-i', 
        action='store_true',
        help='Mode interactif avec menu'
    )
    
    args = parser.parse_args()
    
    # Mode interactif
    if args.interactive or not args.domain:
        show_interactive_menu()
    else:
        # Mode direct
        success = run_analysis(args.domain, args.output, args.format, args.verbose)
        sys.exit(0 if success else 1)

def main():
if __name__ == "__main__":
    main()