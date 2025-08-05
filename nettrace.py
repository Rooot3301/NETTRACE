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
from utils import DomainAnalyzer, print_banner, print_section, print_success, print_error, print_warning, print_info

def main():
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
    
    args = parser.parse_args()
    
    # Validation du domaine
    domain = args.domain.lower().strip()
    if not domain or '.' not in domain:
        print_error("❌ Domaine invalide. Veuillez spécifier un domaine valide (ex: google.com)")
        sys.exit(1)
    
    print_info(f"🎯 Analyse du domaine: {domain}")
    print_info("=" * 60)
    
    # Initialisation de l'analyseur
    analyzer = DomainAnalyzer(domain, verbose=args.verbose)
    
    try:
        # Exécution de l'analyse complète
        results = analyzer.run_full_analysis()
        
        # Affichage des résultats
        analyzer.display_results(results)
        
        # Export si demandé
        if args.output:
            analyzer.export_results(results, args.output, args.format)
            print_success(f"✅ Rapport sauvegardé: {args.output}")
        
        print_info("\n" + "=" * 60)
        print_success("🎉 Analyse terminée avec succès!")
        
    except KeyboardInterrupt:
        print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()